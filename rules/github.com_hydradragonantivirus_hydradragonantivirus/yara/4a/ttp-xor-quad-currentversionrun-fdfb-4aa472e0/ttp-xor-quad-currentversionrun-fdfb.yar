rule TTP_XOR_QUAD_CurrentVersionRun_fdfb {
  strings:
    $key_fdfb = { ae 94 [2] 8a 9a [2] a1 b6 [2] 8f 94 [2] 9b 8f [2] 94 95 [2] 8a 88 [2] 88 89 [2] 93 8f [2] 8f 88 [2] 93 a7 }

  condition:
    any of them
}