rule TTP_XOR_QUAD_CurrentVersionRun_1725 {
  strings:
    $key_1725 = { 44 4a [2] 60 44 [2] 4b 68 [2] 65 4a [2] 71 51 [2] 7e 4b [2] 60 56 [2] 62 57 [2] 79 51 [2] 65 56 [2] 79 79 }

  condition:
    any of them
}