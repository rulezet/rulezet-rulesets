rule TTP_XOR_QUAD_CurrentVersionRun_ff4d {
  strings:
    $key_ff4d = { ac 22 [2] 88 2c [2] a3 00 [2] 8d 22 [2] 99 39 [2] 96 23 [2] 88 3e [2] 8a 3f [2] 91 39 [2] 8d 3e [2] 91 11 }

  condition:
    any of them
}