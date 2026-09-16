rule TTP_XOR_QUAD_CurrentVersionRun_ff3d {
  strings:
    $key_ff3d = { ac 52 [2] 88 5c [2] a3 70 [2] 8d 52 [2] 99 49 [2] 96 53 [2] 88 4e [2] 8a 4f [2] 91 49 [2] 8d 4e [2] 91 61 }

  condition:
    any of them
}