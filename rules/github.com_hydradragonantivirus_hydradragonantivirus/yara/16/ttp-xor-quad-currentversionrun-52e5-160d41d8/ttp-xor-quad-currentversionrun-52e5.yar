rule TTP_XOR_QUAD_CurrentVersionRun_52e5 {
  strings:
    $key_52e5 = { 01 8a [2] 25 84 [2] 0e a8 [2] 20 8a [2] 34 91 [2] 3b 8b [2] 25 96 [2] 27 97 [2] 3c 91 [2] 20 96 [2] 3c b9 }

  condition:
    any of them
}