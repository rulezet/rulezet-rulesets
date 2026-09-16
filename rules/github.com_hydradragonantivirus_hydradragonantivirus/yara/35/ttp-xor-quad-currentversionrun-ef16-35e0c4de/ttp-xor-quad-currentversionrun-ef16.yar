rule TTP_XOR_QUAD_CurrentVersionRun_ef16 {
  strings:
    $key_ef16 = { bc 79 [2] 98 77 [2] b3 5b [2] 9d 79 [2] 89 62 [2] 86 78 [2] 98 65 [2] 9a 64 [2] 81 62 [2] 9d 65 [2] 81 4a }

  condition:
    any of them
}