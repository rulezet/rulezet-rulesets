rule TTP_XOR_QUAD_CurrentVersionRun_1208 {
  strings:
    $key_1208 = { 41 67 [2] 65 69 [2] 4e 45 [2] 60 67 [2] 74 7c [2] 7b 66 [2] 65 7b [2] 67 7a [2] 7c 7c [2] 60 7b [2] 7c 54 }

  condition:
    any of them
}