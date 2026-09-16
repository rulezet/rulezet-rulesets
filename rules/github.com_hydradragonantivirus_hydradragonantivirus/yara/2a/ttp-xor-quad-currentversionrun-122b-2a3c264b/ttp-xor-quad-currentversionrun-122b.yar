rule TTP_XOR_QUAD_CurrentVersionRun_122b {
  strings:
    $key_122b = { 41 44 [2] 65 4a [2] 4e 66 [2] 60 44 [2] 74 5f [2] 7b 45 [2] 65 58 [2] 67 59 [2] 7c 5f [2] 60 58 [2] 7c 77 }

  condition:
    any of them
}