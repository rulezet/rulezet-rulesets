rule TTP_XOR_QUAD_CurrentVersionRun_0d5f {
  strings:
    $key_0d5f = { 5e 30 [2] 7a 3e [2] 51 12 [2] 7f 30 [2] 6b 2b [2] 64 31 [2] 7a 2c [2] 78 2d [2] 63 2b [2] 7f 2c [2] 63 03 }

  condition:
    any of them
}