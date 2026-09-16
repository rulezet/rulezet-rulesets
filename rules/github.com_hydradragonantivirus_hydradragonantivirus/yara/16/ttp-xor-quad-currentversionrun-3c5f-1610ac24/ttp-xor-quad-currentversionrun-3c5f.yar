rule TTP_XOR_QUAD_CurrentVersionRun_3c5f {
  strings:
    $key_3c5f = { 6f 30 [2] 4b 3e [2] 60 12 [2] 4e 30 [2] 5a 2b [2] 55 31 [2] 4b 2c [2] 49 2d [2] 52 2b [2] 4e 2c [2] 52 03 }

  condition:
    any of them
}