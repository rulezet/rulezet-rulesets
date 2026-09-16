rule TTP_XOR_QUAD_CurrentVersionRun_0614 {
  strings:
    $key_0614 = { 55 7b [2] 71 75 [2] 5a 59 [2] 74 7b [2] 60 60 [2] 6f 7a [2] 71 67 [2] 73 66 [2] 68 60 [2] 74 67 [2] 68 48 }

  condition:
    any of them
}