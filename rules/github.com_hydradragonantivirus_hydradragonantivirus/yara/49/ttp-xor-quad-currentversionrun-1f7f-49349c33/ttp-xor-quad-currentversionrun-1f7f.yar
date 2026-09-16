rule TTP_XOR_QUAD_CurrentVersionRun_1f7f {
  strings:
    $key_1f7f = { 4c 10 [2] 68 1e [2] 43 32 [2] 6d 10 [2] 79 0b [2] 76 11 [2] 68 0c [2] 6a 0d [2] 71 0b [2] 6d 0c [2] 71 23 }

  condition:
    any of them
}