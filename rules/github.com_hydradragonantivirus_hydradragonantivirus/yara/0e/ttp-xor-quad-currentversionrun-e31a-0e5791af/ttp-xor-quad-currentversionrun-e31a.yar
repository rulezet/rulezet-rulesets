rule TTP_XOR_QUAD_CurrentVersionRun_e31a {
  strings:
    $key_e31a = { b0 75 [2] 94 7b [2] bf 57 [2] 91 75 [2] 85 6e [2] 8a 74 [2] 94 69 [2] 96 68 [2] 8d 6e [2] 91 69 [2] 8d 46 }

  condition:
    any of them
}