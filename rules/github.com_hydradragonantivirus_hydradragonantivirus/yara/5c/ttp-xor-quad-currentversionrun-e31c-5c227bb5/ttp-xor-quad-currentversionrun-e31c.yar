rule TTP_XOR_QUAD_CurrentVersionRun_e31c {
  strings:
    $key_e31c = { b0 73 [2] 94 7d [2] bf 51 [2] 91 73 [2] 85 68 [2] 8a 72 [2] 94 6f [2] 96 6e [2] 8d 68 [2] 91 6f [2] 8d 40 }

  condition:
    any of them
}