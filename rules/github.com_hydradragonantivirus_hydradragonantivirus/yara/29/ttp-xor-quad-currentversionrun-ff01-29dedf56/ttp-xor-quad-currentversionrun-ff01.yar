rule TTP_XOR_QUAD_CurrentVersionRun_ff01 {
  strings:
    $key_ff01 = { ac 6e [2] 88 60 [2] a3 4c [2] 8d 6e [2] 99 75 [2] 96 6f [2] 88 72 [2] 8a 73 [2] 91 75 [2] 8d 72 [2] 91 5d }

  condition:
    any of them
}