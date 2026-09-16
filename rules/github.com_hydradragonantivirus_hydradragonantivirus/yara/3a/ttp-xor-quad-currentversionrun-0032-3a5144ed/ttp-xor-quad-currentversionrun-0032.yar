rule TTP_XOR_QUAD_CurrentVersionRun_0032 {
  strings:
    $key_0032 = { 53 5d [2] 77 53 [2] 5c 7f [2] 72 5d [2] 66 46 [2] 69 5c [2] 77 41 [2] 75 40 [2] 6e 46 [2] 72 41 [2] 6e 6e }

  condition:
    any of them
}