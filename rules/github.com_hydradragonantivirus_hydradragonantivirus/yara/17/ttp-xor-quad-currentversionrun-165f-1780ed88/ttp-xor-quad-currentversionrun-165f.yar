rule TTP_XOR_QUAD_CurrentVersionRun_165f {
  strings:
    $key_165f = { 45 30 [2] 61 3e [2] 4a 12 [2] 64 30 [2] 70 2b [2] 7f 31 [2] 61 2c [2] 63 2d [2] 78 2b [2] 64 2c [2] 78 03 }

  condition:
    any of them
}