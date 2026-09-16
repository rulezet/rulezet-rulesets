rule TTP_XOR_QUAD_CurrentVersionRun_12e8 {
  strings:
    $key_12e8 = { 41 87 [2] 65 89 [2] 4e a5 [2] 60 87 [2] 74 9c [2] 7b 86 [2] 65 9b [2] 67 9a [2] 7c 9c [2] 60 9b [2] 7c b4 }

  condition:
    any of them
}