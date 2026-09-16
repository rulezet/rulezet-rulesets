rule TTP_XOR_QUAD_CurrentVersionRun_ff3e {
  strings:
    $key_ff3e = { ac 51 [2] 88 5f [2] a3 73 [2] 8d 51 [2] 99 4a [2] 96 50 [2] 88 4d [2] 8a 4c [2] 91 4a [2] 8d 4d [2] 91 62 }

  condition:
    any of them
}