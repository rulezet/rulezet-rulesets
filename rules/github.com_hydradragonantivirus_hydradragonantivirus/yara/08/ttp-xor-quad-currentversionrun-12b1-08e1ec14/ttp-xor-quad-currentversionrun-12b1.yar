rule TTP_XOR_QUAD_CurrentVersionRun_12b1 {
  strings:
    $key_12b1 = { 41 de [2] 65 d0 [2] 4e fc [2] 60 de [2] 74 c5 [2] 7b df [2] 65 c2 [2] 67 c3 [2] 7c c5 [2] 60 c2 [2] 7c ed }

  condition:
    any of them
}