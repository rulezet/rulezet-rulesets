rule TTP_XOR_QUAD_CurrentVersionRun_1206 {
  strings:
    $key_1206 = { 41 69 [2] 65 67 [2] 4e 4b [2] 60 69 [2] 74 72 [2] 7b 68 [2] 65 75 [2] 67 74 [2] 7c 72 [2] 60 75 [2] 7c 5a }

  condition:
    any of them
}