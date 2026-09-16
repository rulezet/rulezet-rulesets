rule TTP_XOR_QUAD_CurrentVersionRun_ebfb {
  strings:
    $key_ebfb = { b8 94 [2] 9c 9a [2] b7 b6 [2] 99 94 [2] 8d 8f [2] 82 95 [2] 9c 88 [2] 9e 89 [2] 85 8f [2] 99 88 [2] 85 a7 }

  condition:
    any of them
}