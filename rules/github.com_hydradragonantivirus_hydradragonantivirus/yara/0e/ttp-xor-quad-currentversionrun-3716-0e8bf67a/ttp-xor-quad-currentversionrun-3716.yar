rule TTP_XOR_QUAD_CurrentVersionRun_3716 {
  strings:
    $key_3716 = { 64 79 [2] 40 77 [2] 6b 5b [2] 45 79 [2] 51 62 [2] 5e 78 [2] 40 65 [2] 42 64 [2] 59 62 [2] 45 65 [2] 59 4a }

  condition:
    any of them
}