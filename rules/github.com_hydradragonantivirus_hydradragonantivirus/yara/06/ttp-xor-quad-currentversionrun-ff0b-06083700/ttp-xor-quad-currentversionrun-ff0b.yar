rule TTP_XOR_QUAD_CurrentVersionRun_ff0b {
  strings:
    $key_ff0b = { ac 64 [2] 88 6a [2] a3 46 [2] 8d 64 [2] 99 7f [2] 96 65 [2] 88 78 [2] 8a 79 [2] 91 7f [2] 8d 78 [2] 91 57 }

  condition:
    any of them
}