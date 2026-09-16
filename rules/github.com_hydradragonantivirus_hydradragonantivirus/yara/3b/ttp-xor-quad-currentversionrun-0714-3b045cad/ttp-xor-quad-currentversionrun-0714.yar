rule TTP_XOR_QUAD_CurrentVersionRun_0714 {
  strings:
    $key_0714 = { 54 7b [2] 70 75 [2] 5b 59 [2] 75 7b [2] 61 60 [2] 6e 7a [2] 70 67 [2] 72 66 [2] 69 60 [2] 75 67 [2] 69 48 }

  condition:
    any of them
}