rule TTP_XOR_QUAD_CurrentVersionRun_105f {
  strings:
    $key_105f = { 43 30 [2] 67 3e [2] 4c 12 [2] 62 30 [2] 76 2b [2] 79 31 [2] 67 2c [2] 65 2d [2] 7e 2b [2] 62 2c [2] 7e 03 }

  condition:
    any of them
}