rule TTP_XOR_QUAD_CurrentVersionRun_ff3b {
  strings:
    $key_ff3b = { ac 54 [2] 88 5a [2] a3 76 [2] 8d 54 [2] 99 4f [2] 96 55 [2] 88 48 [2] 8a 49 [2] 91 4f [2] 8d 48 [2] 91 67 }

  condition:
    any of them
}