rule TTP_XOR_QUAD_CurrentVersionRun_4035 {
  strings:
    $key_4035 = { 13 5a [2] 37 54 [2] 1c 78 [2] 32 5a [2] 26 41 [2] 29 5b [2] 37 46 [2] 35 47 [2] 2e 41 [2] 32 46 [2] 2e 69 }

  condition:
    any of them
}