rule TTP_XOR_QUAD_CurrentVersionRun_0628 {
  strings:
    $key_0628 = { 55 47 [2] 71 49 [2] 5a 65 [2] 74 47 [2] 60 5c [2] 6f 46 [2] 71 5b [2] 73 5a [2] 68 5c [2] 74 5b [2] 68 74 }

  condition:
    any of them
}