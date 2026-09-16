rule TTP_XOR_QUAD_CurrentVersionRun_e316 {
  strings:
    $key_e316 = { b0 79 [2] 94 77 [2] bf 5b [2] 91 79 [2] 85 62 [2] 8a 78 [2] 94 65 [2] 96 64 [2] 8d 62 [2] 91 65 [2] 8d 4a }

  condition:
    any of them
}