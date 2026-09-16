rule TTP_XOR_QUAD_CurrentVersionRun_2816 {
  strings:
    $key_2816 = { 7b 79 [2] 5f 77 [2] 74 5b [2] 5a 79 [2] 4e 62 [2] 41 78 [2] 5f 65 [2] 5d 64 [2] 46 62 [2] 5a 65 [2] 46 4a }

  condition:
    any of them
}