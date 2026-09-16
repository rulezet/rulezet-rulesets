rule TTP_XOR_QUAD_CurrentVersionRun_e37a {
  strings:
    $key_e37a = { b0 15 [2] 94 1b [2] bf 37 [2] 91 15 [2] 85 0e [2] 8a 14 [2] 94 09 [2] 96 08 [2] 8d 0e [2] 91 09 [2] 8d 26 }

  condition:
    any of them
}