rule TTP_XOR_QUAD_CurrentVersionRun_0bfb {
  strings:
    $key_0bfb = { 58 94 [2] 7c 9a [2] 57 b6 [2] 79 94 [2] 6d 8f [2] 62 95 [2] 7c 88 [2] 7e 89 [2] 65 8f [2] 79 88 [2] 65 a7 }

  condition:
    any of them
}