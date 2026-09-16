rule TTP_XOR_QUAD_CurrentVersionRun_ff6f {
  strings:
    $key_ff6f = { ac 00 [2] 88 0e [2] a3 22 [2] 8d 00 [2] 99 1b [2] 96 01 [2] 88 1c [2] 8a 1d [2] 91 1b [2] 8d 1c [2] 91 33 }

  condition:
    any of them
}