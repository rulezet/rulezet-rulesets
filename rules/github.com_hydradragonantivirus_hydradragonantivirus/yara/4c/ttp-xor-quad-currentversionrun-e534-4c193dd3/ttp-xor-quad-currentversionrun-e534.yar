rule TTP_XOR_QUAD_CurrentVersionRun_e534 {
  strings:
    $key_e534 = { b6 5b [2] 92 55 [2] b9 79 [2] 97 5b [2] 83 40 [2] 8c 5a [2] 92 47 [2] 90 46 [2] 8b 40 [2] 97 47 [2] 8b 68 }

  condition:
    any of them
}