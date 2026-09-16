rule TTP_XOR_QUAD_CurrentVersionRun_ff30 {
  strings:
    $key_ff30 = { ac 5f [2] 88 51 [2] a3 7d [2] 8d 5f [2] 99 44 [2] 96 5e [2] 88 43 [2] 8a 42 [2] 91 44 [2] 8d 43 [2] 91 6c }

  condition:
    any of them
}