rule TTP_XOR_QUAD_CurrentVersionRun_e532 {
  strings:
    $key_e532 = { b6 5d [2] 92 53 [2] b9 7f [2] 97 5d [2] 83 46 [2] 8c 5c [2] 92 41 [2] 90 40 [2] 8b 46 [2] 97 41 [2] 8b 6e }

  condition:
    any of them
}