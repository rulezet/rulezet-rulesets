rule TTP_XOR_QUAD_CurrentVersionRun_ff42 {
  strings:
    $key_ff42 = { ac 2d [2] 88 23 [2] a3 0f [2] 8d 2d [2] 99 36 [2] 96 2c [2] 88 31 [2] 8a 30 [2] 91 36 [2] 8d 31 [2] 91 1e }

  condition:
    any of them
}