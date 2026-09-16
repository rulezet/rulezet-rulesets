rule TTP_XOR_QUAD_CurrentVersionRun_ff32 {
  strings:
    $key_ff32 = { ac 5d [2] 88 53 [2] a3 7f [2] 8d 5d [2] 99 46 [2] 96 5c [2] 88 41 [2] 8a 40 [2] 91 46 [2] 8d 41 [2] 91 6e }

  condition:
    any of them
}