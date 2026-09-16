rule TTP_XOR_QUAD_CurrentVersionRun_12e5 {
  strings:
    $key_12e5 = { 41 8a [2] 65 84 [2] 4e a8 [2] 60 8a [2] 74 91 [2] 7b 8b [2] 65 96 [2] 67 97 [2] 7c 91 [2] 60 96 [2] 7c b9 }

  condition:
    any of them
}