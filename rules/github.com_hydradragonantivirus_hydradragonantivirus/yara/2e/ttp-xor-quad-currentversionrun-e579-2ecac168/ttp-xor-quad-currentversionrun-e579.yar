rule TTP_XOR_QUAD_CurrentVersionRun_e579 {
  strings:
    $key_e579 = { b6 16 [2] 92 18 [2] b9 34 [2] 97 16 [2] 83 0d [2] 8c 17 [2] 92 0a [2] 90 0b [2] 8b 0d [2] 97 0a [2] 8b 25 }

  condition:
    any of them
}