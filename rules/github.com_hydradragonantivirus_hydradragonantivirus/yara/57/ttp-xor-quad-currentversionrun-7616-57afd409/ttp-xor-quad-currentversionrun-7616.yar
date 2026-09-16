rule TTP_XOR_QUAD_CurrentVersionRun_7616 {
  strings:
    $key_7616 = { 25 79 [2] 01 77 [2] 2a 5b [2] 04 79 [2] 10 62 [2] 1f 78 [2] 01 65 [2] 03 64 [2] 18 62 [2] 04 65 [2] 18 4a }

  condition:
    any of them
}