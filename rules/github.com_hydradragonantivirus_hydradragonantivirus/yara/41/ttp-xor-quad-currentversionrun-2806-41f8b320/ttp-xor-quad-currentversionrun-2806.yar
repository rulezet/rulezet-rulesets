rule TTP_XOR_QUAD_CurrentVersionRun_2806 {
  strings:
    $key_2806 = { 7b 69 [2] 5f 67 [2] 74 4b [2] 5a 69 [2] 4e 72 [2] 41 68 [2] 5f 75 [2] 5d 74 [2] 46 72 [2] 5a 75 [2] 46 5a }

  condition:
    any of them
}