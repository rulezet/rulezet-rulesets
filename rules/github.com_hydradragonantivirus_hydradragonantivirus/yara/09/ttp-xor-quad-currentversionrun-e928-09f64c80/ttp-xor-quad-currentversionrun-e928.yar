rule TTP_XOR_QUAD_CurrentVersionRun_e928 {
  strings:
    $key_e928 = { ba 47 [2] 9e 49 [2] b5 65 [2] 9b 47 [2] 8f 5c [2] 80 46 [2] 9e 5b [2] 9c 5a [2] 87 5c [2] 9b 5b [2] 87 74 }

  condition:
    any of them
}