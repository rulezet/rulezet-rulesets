rule TTP_XOR_QUAD_CurrentVersionRun_e528 {
  strings:
    $key_e528 = { b6 47 [2] 92 49 [2] b9 65 [2] 97 47 [2] 83 5c [2] 8c 46 [2] 92 5b [2] 90 5a [2] 8b 5c [2] 97 5b [2] 8b 74 }

  condition:
    any of them
}