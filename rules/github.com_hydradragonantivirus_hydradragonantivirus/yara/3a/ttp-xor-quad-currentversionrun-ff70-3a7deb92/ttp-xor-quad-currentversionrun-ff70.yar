rule TTP_XOR_QUAD_CurrentVersionRun_ff70 {
  strings:
    $key_ff70 = { ac 1f [2] 88 11 [2] a3 3d [2] 8d 1f [2] 99 04 [2] 96 1e [2] 88 03 [2] 8a 02 [2] 91 04 [2] 8d 03 [2] 91 2c }

  condition:
    any of them
}