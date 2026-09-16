rule TTP_XOR_QUAD_CurrentVersionRun_175f {
  strings:
    $key_175f = { 44 30 [2] 60 3e [2] 4b 12 [2] 65 30 [2] 71 2b [2] 7e 31 [2] 60 2c [2] 62 2d [2] 79 2b [2] 65 2c [2] 79 03 }

  condition:
    any of them
}