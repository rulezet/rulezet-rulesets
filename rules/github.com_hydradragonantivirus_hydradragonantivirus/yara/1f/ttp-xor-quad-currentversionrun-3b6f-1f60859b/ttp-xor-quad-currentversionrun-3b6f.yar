rule TTP_XOR_QUAD_CurrentVersionRun_3b6f {
  strings:
    $key_3b6f = { 68 00 [2] 4c 0e [2] 67 22 [2] 49 00 [2] 5d 1b [2] 52 01 [2] 4c 1c [2] 4e 1d [2] 55 1b [2] 49 1c [2] 55 33 }

  condition:
    any of them
}