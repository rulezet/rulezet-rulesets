rule TTP_XOR_QUAD_CurrentVersionRun_ff5b {
  strings:
    $key_ff5b = { ac 34 [2] 88 3a [2] a3 16 [2] 8d 34 [2] 99 2f [2] 96 35 [2] 88 28 [2] 8a 29 [2] 91 2f [2] 8d 28 [2] 91 07 }

  condition:
    any of them
}