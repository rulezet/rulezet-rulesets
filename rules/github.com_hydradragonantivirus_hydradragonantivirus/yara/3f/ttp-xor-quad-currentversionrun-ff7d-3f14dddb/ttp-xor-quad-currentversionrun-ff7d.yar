rule TTP_XOR_QUAD_CurrentVersionRun_ff7d {
  strings:
    $key_ff7d = { ac 12 [2] 88 1c [2] a3 30 [2] 8d 12 [2] 99 09 [2] 96 13 [2] 88 0e [2] 8a 0f [2] 91 09 [2] 8d 0e [2] 91 21 }

  condition:
    any of them
}