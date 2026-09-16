rule TTP_XOR_QUAD_CurrentVersionRun_2906 {
  strings:
    $key_2906 = { 7a 69 [2] 5e 67 [2] 75 4b [2] 5b 69 [2] 4f 72 [2] 40 68 [2] 5e 75 [2] 5c 74 [2] 47 72 [2] 5b 75 [2] 47 5a }

  condition:
    any of them
}