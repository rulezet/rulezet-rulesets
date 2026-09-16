rule TTP_XOR_QUAD_CurrentVersionRun_12e9 {
  strings:
    $key_12e9 = { 41 86 [2] 65 88 [2] 4e a4 [2] 60 86 [2] 74 9d [2] 7b 87 [2] 65 9a [2] 67 9b [2] 7c 9d [2] 60 9a [2] 7c b5 }

  condition:
    any of them
}