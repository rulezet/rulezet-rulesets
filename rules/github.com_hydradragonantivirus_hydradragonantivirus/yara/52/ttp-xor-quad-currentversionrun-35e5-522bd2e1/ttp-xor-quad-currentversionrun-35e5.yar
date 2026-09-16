rule TTP_XOR_QUAD_CurrentVersionRun_35e5 {
  strings:
    $key_35e5 = { 66 8a [2] 42 84 [2] 69 a8 [2] 47 8a [2] 53 91 [2] 5c 8b [2] 42 96 [2] 40 97 [2] 5b 91 [2] 47 96 [2] 5b b9 }

  condition:
    any of them
}