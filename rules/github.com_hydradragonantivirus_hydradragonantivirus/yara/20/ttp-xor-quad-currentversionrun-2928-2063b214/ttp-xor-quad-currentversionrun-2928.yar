rule TTP_XOR_QUAD_CurrentVersionRun_2928 {
  strings:
    $key_2928 = { 7a 47 [2] 5e 49 [2] 75 65 [2] 5b 47 [2] 4f 5c [2] 40 46 [2] 5e 5b [2] 5c 5a [2] 47 5c [2] 5b 5b [2] 47 74 }

  condition:
    any of them
}