rule TTP_XOR_QUAD_CurrentVersionRun_1d7f {
  strings:
    $key_1d7f = { 4e 10 [2] 6a 1e [2] 41 32 [2] 6f 10 [2] 7b 0b [2] 74 11 [2] 6a 0c [2] 68 0d [2] 73 0b [2] 6f 0c [2] 73 23 }

  condition:
    any of them
}