rule TTP_XOR_QUAD_CurrentVersionRun_1218 {
  strings:
    $key_1218 = { 41 77 [2] 65 79 [2] 4e 55 [2] 60 77 [2] 74 6c [2] 7b 76 [2] 65 6b [2] 67 6a [2] 7c 6c [2] 60 6b [2] 7c 44 }

  condition:
    any of them
}