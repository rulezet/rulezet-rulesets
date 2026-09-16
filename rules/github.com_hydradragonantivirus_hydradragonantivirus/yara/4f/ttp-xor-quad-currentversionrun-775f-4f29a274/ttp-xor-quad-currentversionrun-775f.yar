rule TTP_XOR_QUAD_CurrentVersionRun_775f {
  strings:
    $key_775f = { 24 30 [2] 00 3e [2] 2b 12 [2] 05 30 [2] 11 2b [2] 1e 31 [2] 00 2c [2] 02 2d [2] 19 2b [2] 05 2c [2] 19 03 }

  condition:
    any of them
}