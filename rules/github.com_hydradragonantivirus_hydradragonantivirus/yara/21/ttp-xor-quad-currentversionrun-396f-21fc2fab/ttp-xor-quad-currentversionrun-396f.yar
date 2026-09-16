rule TTP_XOR_QUAD_CurrentVersionRun_396f {
  strings:
    $key_396f = { 6a 00 [2] 4e 0e [2] 65 22 [2] 4b 00 [2] 5f 1b [2] 50 01 [2] 4e 1c [2] 4c 1d [2] 57 1b [2] 4b 1c [2] 57 33 }

  condition:
    any of them
}