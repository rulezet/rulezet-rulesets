rule TTP_XOR_QUAD_CurrentVersionRun_155f {
  strings:
    $key_155f = { 46 30 [2] 62 3e [2] 49 12 [2] 67 30 [2] 73 2b [2] 7c 31 [2] 62 2c [2] 60 2d [2] 7b 2b [2] 67 2c [2] 7b 03 }

  condition:
    any of them
}