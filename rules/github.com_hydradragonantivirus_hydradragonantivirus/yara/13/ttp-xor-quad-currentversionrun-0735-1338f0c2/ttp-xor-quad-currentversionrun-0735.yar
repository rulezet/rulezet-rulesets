rule TTP_XOR_QUAD_CurrentVersionRun_0735 {
  strings:
    $key_0735 = { 54 5a [2] 70 54 [2] 5b 78 [2] 75 5a [2] 61 41 [2] 6e 5b [2] 70 46 [2] 72 47 [2] 69 41 [2] 75 46 [2] 69 69 }

  condition:
    any of them
}