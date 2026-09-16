rule TTP_XOR_QUAD_CurrentVersionRun_1514 {
  strings:
    $key_1514 = { 46 7b [2] 62 75 [2] 49 59 [2] 67 7b [2] 73 60 [2] 7c 7a [2] 62 67 [2] 60 66 [2] 7b 60 [2] 67 67 [2] 7b 48 }

  condition:
    any of them
}