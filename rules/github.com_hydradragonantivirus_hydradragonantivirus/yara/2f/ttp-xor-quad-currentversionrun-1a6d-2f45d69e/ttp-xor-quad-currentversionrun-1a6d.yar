rule TTP_XOR_QUAD_CurrentVersionRun_1a6d {
  strings:
    $key_1a6d = { 49 02 [2] 6d 0c [2] 46 20 [2] 68 02 [2] 7c 19 [2] 73 03 [2] 6d 1e [2] 6f 1f [2] 74 19 [2] 68 1e [2] 74 31 }

  condition:
    any of them
}