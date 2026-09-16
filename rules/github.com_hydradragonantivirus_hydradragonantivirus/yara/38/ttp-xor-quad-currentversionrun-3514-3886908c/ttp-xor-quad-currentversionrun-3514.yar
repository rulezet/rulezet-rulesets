rule TTP_XOR_QUAD_CurrentVersionRun_3514 {
  strings:
    $key_3514 = { 66 7b [2] 42 75 [2] 69 59 [2] 47 7b [2] 53 60 [2] 5c 7a [2] 42 67 [2] 40 66 [2] 5b 60 [2] 47 67 [2] 5b 48 }

  condition:
    any of them
}