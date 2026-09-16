rule TTP_XOR_QUAD_CurrentVersionRun_392b {
  strings:
    $key_392b = { 6a 44 [2] 4e 4a [2] 65 66 [2] 4b 44 [2] 5f 5f [2] 50 45 [2] 4e 58 [2] 4c 59 [2] 57 5f [2] 4b 58 [2] 57 77 }

  condition:
    any of them
}