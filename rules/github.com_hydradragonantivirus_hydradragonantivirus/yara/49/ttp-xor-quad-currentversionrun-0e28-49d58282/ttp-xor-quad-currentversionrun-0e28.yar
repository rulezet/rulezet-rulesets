rule TTP_XOR_QUAD_CurrentVersionRun_0e28 {
  strings:
    $key_0e28 = { 5d 47 [2] 79 49 [2] 52 65 [2] 7c 47 [2] 68 5c [2] 67 46 [2] 79 5b [2] 7b 5a [2] 60 5c [2] 7c 5b [2] 60 74 }

  condition:
    any of them
}