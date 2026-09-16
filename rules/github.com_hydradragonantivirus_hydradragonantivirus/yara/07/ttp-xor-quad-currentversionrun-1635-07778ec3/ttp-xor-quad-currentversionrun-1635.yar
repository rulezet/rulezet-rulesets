rule TTP_XOR_QUAD_CurrentVersionRun_1635 {
  strings:
    $key_1635 = { 45 5a [2] 61 54 [2] 4a 78 [2] 64 5a [2] 70 41 [2] 7f 5b [2] 61 46 [2] 63 47 [2] 78 41 [2] 64 46 [2] 78 69 }

  condition:
    any of them
}