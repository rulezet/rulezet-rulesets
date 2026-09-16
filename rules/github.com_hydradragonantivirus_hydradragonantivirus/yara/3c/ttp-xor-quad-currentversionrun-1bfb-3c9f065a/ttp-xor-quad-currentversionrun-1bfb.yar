rule TTP_XOR_QUAD_CurrentVersionRun_1bfb {
  strings:
    $key_1bfb = { 48 94 [2] 6c 9a [2] 47 b6 [2] 69 94 [2] 7d 8f [2] 72 95 [2] 6c 88 [2] 6e 89 [2] 75 8f [2] 69 88 [2] 75 a7 }

  condition:
    any of them
}