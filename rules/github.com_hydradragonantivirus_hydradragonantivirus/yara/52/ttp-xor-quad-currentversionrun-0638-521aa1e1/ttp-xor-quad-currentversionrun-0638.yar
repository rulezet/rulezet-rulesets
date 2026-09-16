rule TTP_XOR_QUAD_CurrentVersionRun_0638 {
  strings:
    $key_0638 = { 55 57 [2] 71 59 [2] 5a 75 [2] 74 57 [2] 60 4c [2] 6f 56 [2] 71 4b [2] 73 4a [2] 68 4c [2] 74 4b [2] 68 64 }

  condition:
    any of them
}