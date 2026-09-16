rule TTP_XOR_QUAD_CurrentVersionRun_3516 {
  strings:
    $key_3516 = { 66 79 [2] 42 77 [2] 69 5b [2] 47 79 [2] 53 62 [2] 5c 78 [2] 42 65 [2] 40 64 [2] 5b 62 [2] 47 65 [2] 5b 4a }

  condition:
    any of them
}