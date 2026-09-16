rule TTP_XOR_QUAD_CurrentVersionRun_0908 {
  strings:
    $key_0908 = { 5a 67 [2] 7e 69 [2] 55 45 [2] 7b 67 [2] 6f 7c [2] 60 66 [2] 7e 7b [2] 7c 7a [2] 67 7c [2] 7b 7b [2] 67 54 }

  condition:
    any of them
}