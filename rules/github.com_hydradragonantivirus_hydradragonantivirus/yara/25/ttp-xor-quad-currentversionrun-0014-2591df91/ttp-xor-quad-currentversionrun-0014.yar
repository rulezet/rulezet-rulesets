rule TTP_XOR_QUAD_CurrentVersionRun_0014 {
  strings:
    $key_0014 = { 53 7b [2] 77 75 [2] 5c 59 [2] 72 7b [2] 66 60 [2] 69 7a [2] 77 67 [2] 75 66 [2] 6e 60 [2] 72 67 [2] 6e 48 }

  condition:
    any of them
}