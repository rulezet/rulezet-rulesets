rule TTP_XOR_QUAD_CurrentVersionRun_3935 {
  strings:
    $key_3935 = { 6a 5a [2] 4e 54 [2] 65 78 [2] 4b 5a [2] 5f 41 [2] 50 5b [2] 4e 46 [2] 4c 47 [2] 57 41 [2] 4b 46 [2] 57 69 }

  condition:
    any of them
}