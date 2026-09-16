rule TTP_XOR_QUAD_CurrentVersionRun_3235 {
  strings:
    $key_3235 = { 61 5a [2] 45 54 [2] 6e 78 [2] 40 5a [2] 54 41 [2] 5b 5b [2] 45 46 [2] 47 47 [2] 5c 41 [2] 40 46 [2] 5c 69 }

  condition:
    any of them
}