rule TTP_XOR_QUAD_CurrentVersionRun_3016 {
  strings:
    $key_3016 = { 63 79 [2] 47 77 [2] 6c 5b [2] 42 79 [2] 56 62 [2] 59 78 [2] 47 65 [2] 45 64 [2] 5e 62 [2] 42 65 [2] 5e 4a }

  condition:
    any of them
}