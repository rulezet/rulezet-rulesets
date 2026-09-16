rule TTP_XOR_QUAD_CurrentVersionRun_f116 {
  strings:
    $key_f116 = { a2 79 [2] 86 77 [2] ad 5b [2] 83 79 [2] 97 62 [2] 98 78 [2] 86 65 [2] 84 64 [2] 9f 62 [2] 83 65 [2] 9f 4a }

  condition:
    any of them
}