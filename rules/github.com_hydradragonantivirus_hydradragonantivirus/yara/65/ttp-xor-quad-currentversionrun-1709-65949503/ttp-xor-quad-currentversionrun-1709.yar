rule TTP_XOR_QUAD_CurrentVersionRun_1709 {
  strings:
    $key_1709 = { 44 66 [2] 60 68 [2] 4b 44 [2] 65 66 [2] 71 7d [2] 7e 67 [2] 60 7a [2] 62 7b [2] 79 7d [2] 65 7a [2] 79 55 }

  condition:
    any of them
}