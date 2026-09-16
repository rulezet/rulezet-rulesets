rule TTP_XOR_QUAD_CurrentVersionRun_ff5c {
  strings:
    $key_ff5c = { ac 33 [2] 88 3d [2] a3 11 [2] 8d 33 [2] 99 28 [2] 96 32 [2] 88 2f [2] 8a 2e [2] 91 28 [2] 8d 2f [2] 91 00 }

  condition:
    any of them
}