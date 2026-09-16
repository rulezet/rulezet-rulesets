rule TTP_XOR_QUAD_CurrentVersionRun_ff6e {
  strings:
    $key_ff6e = { ac 01 [2] 88 0f [2] a3 23 [2] 8d 01 [2] 99 1a [2] 96 00 [2] 88 1d [2] 8a 1c [2] 91 1a [2] 8d 1d [2] 91 32 }

  condition:
    any of them
}