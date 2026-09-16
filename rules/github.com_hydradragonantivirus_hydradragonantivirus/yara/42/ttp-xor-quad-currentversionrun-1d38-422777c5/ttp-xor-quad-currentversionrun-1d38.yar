rule TTP_XOR_QUAD_CurrentVersionRun_1d38 {
  strings:
    $key_1d38 = { 4e 57 [2] 6a 59 [2] 41 75 [2] 6f 57 [2] 7b 4c [2] 74 56 [2] 6a 4b [2] 68 4a [2] 73 4c [2] 6f 4b [2] 73 64 }

  condition:
    any of them
}