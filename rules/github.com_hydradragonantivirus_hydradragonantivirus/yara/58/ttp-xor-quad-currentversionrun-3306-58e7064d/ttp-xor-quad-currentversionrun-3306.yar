rule TTP_XOR_QUAD_CurrentVersionRun_3306 {
  strings:
    $key_3306 = { 60 69 [2] 44 67 [2] 6f 4b [2] 41 69 [2] 55 72 [2] 5a 68 [2] 44 75 [2] 46 74 [2] 5d 72 [2] 41 75 [2] 5d 5a }

  condition:
    any of them
}