rule TTP_XOR_QUAD_CurrentVersionRun_f86f {
  strings:
    $key_f86f = { ab 00 [2] 8f 0e [2] a4 22 [2] 8a 00 [2] 9e 1b [2] 91 01 [2] 8f 1c [2] 8d 1d [2] 96 1b [2] 8a 1c [2] 96 33 }

  condition:
    any of them
}