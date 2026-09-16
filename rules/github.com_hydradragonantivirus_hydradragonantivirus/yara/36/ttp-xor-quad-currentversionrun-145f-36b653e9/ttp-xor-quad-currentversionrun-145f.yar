rule TTP_XOR_QUAD_CurrentVersionRun_145f {
  strings:
    $key_145f = { 47 30 [2] 63 3e [2] 48 12 [2] 66 30 [2] 72 2b [2] 7d 31 [2] 63 2c [2] 61 2d [2] 7a 2b [2] 66 2c [2] 7a 03 }

  condition:
    any of them
}