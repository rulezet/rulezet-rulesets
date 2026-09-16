rule TTP_XOR_QUAD_CurrentVersionRun_ff4e {
  strings:
    $key_ff4e = { ac 21 [2] 88 2f [2] a3 03 [2] 8d 21 [2] 99 3a [2] 96 20 [2] 88 3d [2] 8a 3c [2] 91 3a [2] 8d 3d [2] 91 12 }

  condition:
    any of them
}