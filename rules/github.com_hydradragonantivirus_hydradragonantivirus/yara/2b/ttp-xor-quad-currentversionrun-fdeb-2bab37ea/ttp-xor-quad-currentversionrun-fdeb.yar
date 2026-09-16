rule TTP_XOR_QUAD_CurrentVersionRun_fdeb {
  strings:
    $key_fdeb = { ae 84 [2] 8a 8a [2] a1 a6 [2] 8f 84 [2] 9b 9f [2] 94 85 [2] 8a 98 [2] 88 99 [2] 93 9f [2] 8f 98 [2] 93 b7 }

  condition:
    any of them
}