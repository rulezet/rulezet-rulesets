rule TTP_XOR_QUAD_CurrentVersionRun_e544 {
  strings:
    $key_e544 = { b6 2b [2] 92 25 [2] b9 09 [2] 97 2b [2] 83 30 [2] 8c 2a [2] 92 37 [2] 90 36 [2] 8b 30 [2] 97 37 [2] 8b 18 }

  condition:
    any of them
}