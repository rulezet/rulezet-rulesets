rule TTP_XOR_QUAD_CurrentVersionRun_1a7f {
  strings:
    $key_1a7f = { 49 10 [2] 6d 1e [2] 46 32 [2] 68 10 [2] 7c 0b [2] 73 11 [2] 6d 0c [2] 6f 0d [2] 74 0b [2] 68 0c [2] 74 23 }

  condition:
    any of them
}