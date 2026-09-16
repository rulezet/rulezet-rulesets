rule TTP_XOR_QUAD_CurrentVersionRun_125f {
  strings:
    $key_125f = { 41 30 [2] 65 3e [2] 4e 12 [2] 60 30 [2] 74 2b [2] 7b 31 [2] 65 2c [2] 67 2d [2] 7c 2b [2] 60 2c [2] 7c 03 }

  condition:
    any of them
}