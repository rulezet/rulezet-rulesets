rule TTP_XOR_QUAD_CurrentVersionRun_5735 {
  strings:
    $key_5735 = { 04 5a [2] 20 54 [2] 0b 78 [2] 25 5a [2] 31 41 [2] 3e 5b [2] 20 46 [2] 22 47 [2] 39 41 [2] 25 46 [2] 39 69 }

  condition:
    any of them
}