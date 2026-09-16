rule TTP_XOR_QUAD_CurrentVersionRun_62b1 {
  strings:
    $key_62b1 = { 31 de [2] 15 d0 [2] 3e fc [2] 10 de [2] 04 c5 [2] 0b df [2] 15 c2 [2] 17 c3 [2] 0c c5 [2] 10 c2 [2] 0c ed }

  condition:
    any of them
}