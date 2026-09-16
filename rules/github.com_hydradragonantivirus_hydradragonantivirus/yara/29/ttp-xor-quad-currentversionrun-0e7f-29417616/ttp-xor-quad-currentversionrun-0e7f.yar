rule TTP_XOR_QUAD_CurrentVersionRun_0e7f {
  strings:
    $key_0e7f = { 5d 10 [2] 79 1e [2] 52 32 [2] 7c 10 [2] 68 0b [2] 67 11 [2] 79 0c [2] 7b 0d [2] 60 0b [2] 7c 0c [2] 60 23 }

  condition:
    any of them
}