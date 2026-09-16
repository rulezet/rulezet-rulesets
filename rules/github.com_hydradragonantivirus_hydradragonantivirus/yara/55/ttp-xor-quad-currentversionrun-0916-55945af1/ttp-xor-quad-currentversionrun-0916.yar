rule TTP_XOR_QUAD_CurrentVersionRun_0916 {
  strings:
    $key_0916 = { 5a 79 [2] 7e 77 [2] 55 5b [2] 7b 79 [2] 6f 62 [2] 60 78 [2] 7e 65 [2] 7c 64 [2] 67 62 [2] 7b 65 [2] 67 4a }

  condition:
    any of them
}