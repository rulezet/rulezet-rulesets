rule TTP_XOR_QUAD_CurrentVersionRun_1778 {
  strings:
    $key_1778 = { 44 17 [2] 60 19 [2] 4b 35 [2] 65 17 [2] 71 0c [2] 7e 16 [2] 60 0b [2] 62 0a [2] 79 0c [2] 65 0b [2] 79 24 }

  condition:
    any of them
}