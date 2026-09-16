rule TTP_XOR_QUAD_CurrentVersionRun_7bfb {
  strings:
    $key_7bfb = { 28 94 [2] 0c 9a [2] 27 b6 [2] 09 94 [2] 1d 8f [2] 12 95 [2] 0c 88 [2] 0e 89 [2] 15 8f [2] 09 88 [2] 15 a7 }

  condition:
    any of them
}