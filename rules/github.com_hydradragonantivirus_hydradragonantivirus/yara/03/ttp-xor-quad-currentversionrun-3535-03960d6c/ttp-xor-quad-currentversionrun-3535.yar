rule TTP_XOR_QUAD_CurrentVersionRun_3535 {
  strings:
    $key_3535 = { 66 5a [2] 42 54 [2] 69 78 [2] 47 5a [2] 53 41 [2] 5c 5b [2] 42 46 [2] 40 47 [2] 5b 41 [2] 47 46 [2] 5b 69 }

  condition:
    any of them
}