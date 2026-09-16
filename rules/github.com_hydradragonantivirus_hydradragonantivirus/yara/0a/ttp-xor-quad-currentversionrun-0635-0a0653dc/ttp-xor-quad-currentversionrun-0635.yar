rule TTP_XOR_QUAD_CurrentVersionRun_0635 {
  strings:
    $key_0635 = { 55 5a [2] 71 54 [2] 5a 78 [2] 74 5a [2] 60 41 [2] 6f 5b [2] 71 46 [2] 73 47 [2] 68 41 [2] 74 46 [2] 68 69 }

  condition:
    any of them
}