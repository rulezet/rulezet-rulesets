rule TTP_XOR_QUAD_CurrentVersionRun_0e19 {
  strings:
    $key_0e19 = { 5d 76 [2] 79 78 [2] 52 54 [2] 7c 76 [2] 68 6d [2] 67 77 [2] 79 6a [2] 7b 6b [2] 60 6d [2] 7c 6a [2] 60 45 }

  condition:
    any of them
}