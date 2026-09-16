rule TTP_XOR_QUAD_CurrentVersionRun_ff41 {
  strings:
    $key_ff41 = { ac 2e [2] 88 20 [2] a3 0c [2] 8d 2e [2] 99 35 [2] 96 2f [2] 88 32 [2] 8a 33 [2] 91 35 [2] 8d 32 [2] 91 1d }

  condition:
    any of them
}