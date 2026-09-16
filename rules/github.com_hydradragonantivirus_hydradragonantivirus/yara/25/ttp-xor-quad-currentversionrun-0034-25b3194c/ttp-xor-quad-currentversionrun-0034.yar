rule TTP_XOR_QUAD_CurrentVersionRun_0034 {
  strings:
    $key_0034 = { 53 5b [2] 77 55 [2] 5c 79 [2] 72 5b [2] 66 40 [2] 69 5a [2] 77 47 [2] 75 46 [2] 6e 40 [2] 72 47 [2] 6e 68 }

  condition:
    any of them
}