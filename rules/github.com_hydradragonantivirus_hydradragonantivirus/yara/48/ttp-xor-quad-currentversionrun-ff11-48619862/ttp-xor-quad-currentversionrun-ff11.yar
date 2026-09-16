rule TTP_XOR_QUAD_CurrentVersionRun_ff11 {
  strings:
    $key_ff11 = { ac 7e [2] 88 70 [2] a3 5c [2] 8d 7e [2] 99 65 [2] 96 7f [2] 88 62 [2] 8a 63 [2] 91 65 [2] 8d 62 [2] 91 4d }

  condition:
    any of them
}