rule TTP_XOR_QUAD_CurrentVersionRun_0e35 {
  strings:
    $key_0e35 = { 5d 5a [2] 79 54 [2] 52 78 [2] 7c 5a [2] 68 41 [2] 67 5b [2] 79 46 [2] 7b 47 [2] 60 41 [2] 7c 46 [2] 60 69 }

  condition:
    any of them
}