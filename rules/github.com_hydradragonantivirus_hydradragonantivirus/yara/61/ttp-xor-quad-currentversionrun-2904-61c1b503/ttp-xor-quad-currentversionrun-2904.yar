rule TTP_XOR_QUAD_CurrentVersionRun_2904 {
  strings:
    $key_2904 = { 7a 6b [2] 5e 65 [2] 75 49 [2] 5b 6b [2] 4f 70 [2] 40 6a [2] 5e 77 [2] 5c 76 [2] 47 70 [2] 5b 77 [2] 47 58 }

  condition:
    any of them
}