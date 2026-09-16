rule TTP_XOR_QUAD_CurrentVersionRun_0e6f {
  strings:
    $key_0e6f = { 5d 00 [2] 79 0e [2] 52 22 [2] 7c 00 [2] 68 1b [2] 67 01 [2] 79 1c [2] 7b 1d [2] 60 1b [2] 7c 1c [2] 60 33 }

  condition:
    any of them
}