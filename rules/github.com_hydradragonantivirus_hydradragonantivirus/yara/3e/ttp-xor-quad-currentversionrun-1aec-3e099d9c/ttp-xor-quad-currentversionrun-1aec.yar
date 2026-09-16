rule TTP_XOR_QUAD_CurrentVersionRun_1aec {
  strings:
    $key_1aec = { 49 83 [2] 6d 8d [2] 46 a1 [2] 68 83 [2] 7c 98 [2] 73 82 [2] 6d 9f [2] 6f 9e [2] 74 98 [2] 68 9f [2] 74 b0 }

  condition:
    any of them
}