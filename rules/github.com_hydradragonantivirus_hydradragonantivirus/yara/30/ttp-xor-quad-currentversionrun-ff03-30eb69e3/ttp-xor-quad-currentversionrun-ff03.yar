rule TTP_XOR_QUAD_CurrentVersionRun_ff03 {
  strings:
    $key_ff03 = { ac 6c [2] 88 62 [2] a3 4e [2] 8d 6c [2] 99 77 [2] 96 6d [2] 88 70 [2] 8a 71 [2] 91 77 [2] 8d 70 [2] 91 5f }

  condition:
    any of them
}