rule TTP_XOR_QUAD_CurrentVersionRun_1816 {
  strings:
    $key_1816 = { 4b 79 [2] 6f 77 [2] 44 5b [2] 6a 79 [2] 7e 62 [2] 71 78 [2] 6f 65 [2] 6d 64 [2] 76 62 [2] 6a 65 [2] 76 4a }

  condition:
    any of them
}