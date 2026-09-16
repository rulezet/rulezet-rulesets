rule TTP_XOR_QUAD_CurrentVersionRun_2616 {
  strings:
    $key_2616 = { 75 79 [2] 51 77 [2] 7a 5b [2] 54 79 [2] 40 62 [2] 4f 78 [2] 51 65 [2] 53 64 [2] 48 62 [2] 54 65 [2] 48 4a }

  condition:
    any of them
}