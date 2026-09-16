rule TTP_XOR_QUAD_CurrentVersionRun_1719 {
  strings:
    $key_1719 = { 44 76 [2] 60 78 [2] 4b 54 [2] 65 76 [2] 71 6d [2] 7e 77 [2] 60 6a [2] 62 6b [2] 79 6d [2] 65 6a [2] 79 45 }

  condition:
    any of them
}