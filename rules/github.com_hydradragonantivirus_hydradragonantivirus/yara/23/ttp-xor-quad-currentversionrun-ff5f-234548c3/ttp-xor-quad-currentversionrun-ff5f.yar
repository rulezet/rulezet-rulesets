rule TTP_XOR_QUAD_CurrentVersionRun_ff5f {
  strings:
    $key_ff5f = { ac 30 [2] 88 3e [2] a3 12 [2] 8d 30 [2] 99 2b [2] 96 31 [2] 88 2c [2] 8a 2d [2] 91 2b [2] 8d 2c [2] 91 03 }

  condition:
    any of them
}