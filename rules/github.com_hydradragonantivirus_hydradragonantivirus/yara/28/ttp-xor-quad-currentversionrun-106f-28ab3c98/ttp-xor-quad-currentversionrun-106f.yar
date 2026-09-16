rule TTP_XOR_QUAD_CurrentVersionRun_106f {
  strings:
    $key_106f = { 43 00 [2] 67 0e [2] 4c 22 [2] 62 00 [2] 76 1b [2] 79 01 [2] 67 1c [2] 65 1d [2] 7e 1b [2] 62 1c [2] 7e 33 }

  condition:
    any of them
}