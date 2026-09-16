rule TTP_XOR_QUAD_CurrentVersionRun_ff5d {
  strings:
    $key_ff5d = { ac 32 [2] 88 3c [2] a3 10 [2] 8d 32 [2] 99 29 [2] 96 33 [2] 88 2e [2] 8a 2f [2] 91 29 [2] 8d 2e [2] 91 01 }

  condition:
    any of them
}