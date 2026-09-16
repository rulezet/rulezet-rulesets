rule TTP_XOR_QUAD_CurrentVersionRun_1708 {
  strings:
    $key_1708 = { 44 67 [2] 60 69 [2] 4b 45 [2] 65 67 [2] 71 7c [2] 7e 66 [2] 60 7b [2] 62 7a [2] 79 7c [2] 65 7b [2] 79 54 }

  condition:
    any of them
}