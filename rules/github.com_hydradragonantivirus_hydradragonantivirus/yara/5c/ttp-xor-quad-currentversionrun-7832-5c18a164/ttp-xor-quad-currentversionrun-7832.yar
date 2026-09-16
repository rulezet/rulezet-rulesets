rule TTP_XOR_QUAD_CurrentVersionRun_7832 {
  strings:
    $key_7832 = { 2b 5d [2] 0f 53 [2] 24 7f [2] 0a 5d [2] 1e 46 [2] 11 5c [2] 0f 41 [2] 0d 40 [2] 16 46 [2] 0a 41 [2] 16 6e }

  condition:
    any of them
}