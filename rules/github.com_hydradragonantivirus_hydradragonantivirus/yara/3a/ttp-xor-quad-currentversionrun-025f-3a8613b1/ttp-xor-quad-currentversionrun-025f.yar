rule TTP_XOR_QUAD_CurrentVersionRun_025f {
  strings:
    $key_025f = { 51 30 [2] 75 3e [2] 5e 12 [2] 70 30 [2] 64 2b [2] 6b 31 [2] 75 2c [2] 77 2d [2] 6c 2b [2] 70 2c [2] 6c 03 }

  condition:
    any of them
}