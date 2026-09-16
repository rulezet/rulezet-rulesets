rule TTP_XOR_QUAD_CurrentVersionRun_ff26 {
  strings:
    $key_ff26 = { ac 49 [2] 88 47 [2] a3 6b [2] 8d 49 [2] 99 52 [2] 96 48 [2] 88 55 [2] 8a 54 [2] 91 52 [2] 8d 55 [2] 91 7a }

  condition:
    any of them
}