rule TTP_XOR_QUAD_CurrentVersionRun_ff06 {
  strings:
    $key_ff06 = { ac 69 [2] 88 67 [2] a3 4b [2] 8d 69 [2] 99 72 [2] 96 68 [2] 88 75 [2] 8a 74 [2] 91 72 [2] 8d 75 [2] 91 5a }

  condition:
    any of them
}