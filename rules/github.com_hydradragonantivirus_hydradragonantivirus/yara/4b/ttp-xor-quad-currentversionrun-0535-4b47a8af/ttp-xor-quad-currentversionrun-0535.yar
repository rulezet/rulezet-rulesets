rule TTP_XOR_QUAD_CurrentVersionRun_0535 {
  strings:
    $key_0535 = { 56 5a [2] 72 54 [2] 59 78 [2] 77 5a [2] 63 41 [2] 6c 5b [2] 72 46 [2] 70 47 [2] 6b 41 [2] 77 46 [2] 6b 69 }

  condition:
    any of them
}