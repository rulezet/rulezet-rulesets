rule TTP_XOR_QUAD_CurrentVersionRun_ff29 {
  strings:
    $key_ff29 = { ac 46 [2] 88 48 [2] a3 64 [2] 8d 46 [2] 99 5d [2] 96 47 [2] 88 5a [2] 8a 5b [2] 91 5d [2] 8d 5a [2] 91 75 }

  condition:
    any of them
}