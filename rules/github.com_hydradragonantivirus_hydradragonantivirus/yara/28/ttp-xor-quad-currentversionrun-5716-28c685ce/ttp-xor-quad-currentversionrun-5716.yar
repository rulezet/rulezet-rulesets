rule TTP_XOR_QUAD_CurrentVersionRun_5716 {
  strings:
    $key_5716 = { 04 79 [2] 20 77 [2] 0b 5b [2] 25 79 [2] 31 62 [2] 3e 78 [2] 20 65 [2] 22 64 [2] 39 62 [2] 25 65 [2] 39 4a }

  condition:
    any of them
}