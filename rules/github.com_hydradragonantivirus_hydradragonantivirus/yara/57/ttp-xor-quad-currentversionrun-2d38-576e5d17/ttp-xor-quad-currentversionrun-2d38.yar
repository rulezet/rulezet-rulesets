rule TTP_XOR_QUAD_CurrentVersionRun_2d38 {
  strings:
    $key_2d38 = { 7e 57 [2] 5a 59 [2] 71 75 [2] 5f 57 [2] 4b 4c [2] 44 56 [2] 5a 4b [2] 58 4a [2] 43 4c [2] 5f 4b [2] 43 64 }

  condition:
    any of them
}