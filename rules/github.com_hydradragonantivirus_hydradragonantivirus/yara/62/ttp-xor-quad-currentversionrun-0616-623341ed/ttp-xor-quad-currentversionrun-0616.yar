rule TTP_XOR_QUAD_CurrentVersionRun_0616 {
  strings:
    $key_0616 = { 55 79 [2] 71 77 [2] 5a 5b [2] 74 79 [2] 60 62 [2] 6f 78 [2] 71 65 [2] 73 64 [2] 68 62 [2] 74 65 [2] 68 4a }

  condition:
    any of them
}