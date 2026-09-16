rule TTP_XOR_QUAD_CurrentVersionRun_1d14 {
  strings:
    $key_1d14 = { 4e 7b [2] 6a 75 [2] 41 59 [2] 6f 7b [2] 7b 60 [2] 74 7a [2] 6a 67 [2] 68 66 [2] 73 60 [2] 6f 67 [2] 73 48 }

  condition:
    any of them
}