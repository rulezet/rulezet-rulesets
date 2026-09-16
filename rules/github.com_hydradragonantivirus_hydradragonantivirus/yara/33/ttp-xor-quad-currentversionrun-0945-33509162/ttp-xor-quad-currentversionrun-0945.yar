rule TTP_XOR_QUAD_CurrentVersionRun_0945 {
  strings:
    $key_0945 = { 5a 2a [2] 7e 24 [2] 55 08 [2] 7b 2a [2] 6f 31 [2] 60 2b [2] 7e 36 [2] 7c 37 [2] 67 31 [2] 7b 36 [2] 67 19 }

  condition:
    any of them
}