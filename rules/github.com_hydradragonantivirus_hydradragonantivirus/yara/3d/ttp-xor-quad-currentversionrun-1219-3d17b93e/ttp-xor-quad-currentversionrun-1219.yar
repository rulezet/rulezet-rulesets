rule TTP_XOR_QUAD_CurrentVersionRun_1219 {
  strings:
    $key_1219 = { 41 76 [2] 65 78 [2] 4e 54 [2] 60 76 [2] 74 6d [2] 7b 77 [2] 65 6a [2] 67 6b [2] 7c 6d [2] 60 6a [2] 7c 45 }

  condition:
    any of them
}