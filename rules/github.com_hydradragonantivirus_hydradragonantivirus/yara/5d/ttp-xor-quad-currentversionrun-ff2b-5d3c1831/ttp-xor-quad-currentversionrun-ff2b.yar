rule TTP_XOR_QUAD_CurrentVersionRun_ff2b {
  strings:
    $key_ff2b = { ac 44 [2] 88 4a [2] a3 66 [2] 8d 44 [2] 99 5f [2] 96 45 [2] 88 58 [2] 8a 59 [2] 91 5f [2] 8d 58 [2] 91 77 }

  condition:
    any of them
}