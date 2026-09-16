rule TTP_XOR_QUAD_CurrentVersionRun_0e38 {
  strings:
    $key_0e38 = { 5d 57 [2] 79 59 [2] 52 75 [2] 7c 57 [2] 68 4c [2] 67 56 [2] 79 4b [2] 7b 4a [2] 60 4c [2] 7c 4b [2] 60 64 }

  condition:
    any of them
}