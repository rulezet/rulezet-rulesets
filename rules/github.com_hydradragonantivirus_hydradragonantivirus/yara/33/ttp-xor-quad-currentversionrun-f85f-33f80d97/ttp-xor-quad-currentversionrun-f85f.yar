rule TTP_XOR_QUAD_CurrentVersionRun_f85f {
  strings:
    $key_f85f = { ab 30 [2] 8f 3e [2] a4 12 [2] 8a 30 [2] 9e 2b [2] 91 31 [2] 8f 2c [2] 8d 2d [2] 96 2b [2] 8a 2c [2] 96 03 }

  condition:
    any of them
}