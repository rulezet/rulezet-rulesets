rule TTP_XOR_QUAD_CurrentVersionRun_1718 {
  strings:
    $key_1718 = { 44 77 [2] 60 79 [2] 4b 55 [2] 65 77 [2] 71 6c [2] 7e 76 [2] 60 6b [2] 62 6a [2] 79 6c [2] 65 6b [2] 79 44 }

  condition:
    any of them
}