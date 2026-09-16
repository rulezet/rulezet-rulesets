rule TTP_XOR_QUAD_CurrentVersionRun_292b {
  strings:
    $key_292b = { 7a 44 [2] 5e 4a [2] 75 66 [2] 5b 44 [2] 4f 5f [2] 40 45 [2] 5e 58 [2] 5c 59 [2] 47 5f [2] 5b 58 [2] 47 77 }

  condition:
    any of them
}