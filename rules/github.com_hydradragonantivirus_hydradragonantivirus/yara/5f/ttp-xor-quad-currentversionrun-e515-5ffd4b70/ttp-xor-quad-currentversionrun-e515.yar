rule TTP_XOR_QUAD_CurrentVersionRun_e515 {
  strings:
    $key_e515 = { b6 7a [2] 92 74 [2] b9 58 [2] 97 7a [2] 83 61 [2] 8c 7b [2] 92 66 [2] 90 67 [2] 8b 61 [2] 97 66 [2] 8b 49 }

  condition:
    any of them
}