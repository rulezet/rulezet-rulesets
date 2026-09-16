rule TTP_XOR_QUAD_CurrentVersionRun_ff21 {
  strings:
    $key_ff21 = { ac 4e [2] 88 40 [2] a3 6c [2] 8d 4e [2] 99 55 [2] 96 4f [2] 88 52 [2] 8a 53 [2] 91 55 [2] 8d 52 [2] 91 7d }

  condition:
    any of them
}