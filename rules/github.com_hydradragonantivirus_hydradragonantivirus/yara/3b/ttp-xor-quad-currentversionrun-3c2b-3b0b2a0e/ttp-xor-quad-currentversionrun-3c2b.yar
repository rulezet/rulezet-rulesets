rule TTP_XOR_QUAD_CurrentVersionRun_3c2b {
  strings:
    $key_3c2b = { 6f 44 [2] 4b 4a [2] 60 66 [2] 4e 44 [2] 5a 5f [2] 55 45 [2] 4b 58 [2] 49 59 [2] 52 5f [2] 4e 58 [2] 52 77 }

  condition:
    any of them
}