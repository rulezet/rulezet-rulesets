rule TTP_XOR_QUAD_CurrentVersionRun_ff3a {
  strings:
    $key_ff3a = { ac 55 [2] 88 5b [2] a3 77 [2] 8d 55 [2] 99 4e [2] 96 54 [2] 88 49 [2] 8a 48 [2] 91 4e [2] 8d 49 [2] 91 66 }

  condition:
    any of them
}