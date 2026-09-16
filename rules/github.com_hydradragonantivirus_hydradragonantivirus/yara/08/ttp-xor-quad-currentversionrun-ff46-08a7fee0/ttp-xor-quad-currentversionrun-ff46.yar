rule TTP_XOR_QUAD_CurrentVersionRun_ff46 {
  strings:
    $key_ff46 = { ac 29 [2] 88 27 [2] a3 0b [2] 8d 29 [2] 99 32 [2] 96 28 [2] 88 35 [2] 8a 34 [2] 91 32 [2] 8d 35 [2] 91 1a }

  condition:
    any of them
}