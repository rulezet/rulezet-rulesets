rule TTP_XOR_QUAD_CurrentVersionRun_0235 {
  strings:
    $key_0235 = { 51 5a [2] 75 54 [2] 5e 78 [2] 70 5a [2] 64 41 [2] 6b 5b [2] 75 46 [2] 77 47 [2] 6c 41 [2] 70 46 [2] 6c 69 }

  condition:
    any of them
}