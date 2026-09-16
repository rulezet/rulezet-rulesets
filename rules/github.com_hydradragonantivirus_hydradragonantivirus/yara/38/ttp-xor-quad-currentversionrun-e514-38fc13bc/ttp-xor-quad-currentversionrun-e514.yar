rule TTP_XOR_QUAD_CurrentVersionRun_e514 {
  strings:
    $key_e514 = { b6 7b [2] 92 75 [2] b9 59 [2] 97 7b [2] 83 60 [2] 8c 7a [2] 92 67 [2] 90 66 [2] 8b 60 [2] 97 67 [2] 8b 48 }

  condition:
    any of them
}