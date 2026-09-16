rule TTP_XOR_QUAD_CurrentVersionRun_1a7c {
  strings:
    $key_1a7c = { 49 13 [2] 6d 1d [2] 46 31 [2] 68 13 [2] 7c 08 [2] 73 12 [2] 6d 0f [2] 6f 0e [2] 74 08 [2] 68 0f [2] 74 20 }

  condition:
    any of them
}