rule TTP_XOR_QUAD_CurrentVersionRun_defb {
  strings:
    $key_defb = { 8d 94 [2] a9 9a [2] 82 b6 [2] ac 94 [2] b8 8f [2] b7 95 [2] a9 88 [2] ab 89 [2] b0 8f [2] ac 88 [2] b0 a7 }

  condition:
    any of them
}