rule TTP_XOR_QUAD_CurrentVersionRun_fe2b {
  strings:
    $key_fe2b = { ad 44 [2] 89 4a [2] a2 66 [2] 8c 44 [2] 98 5f [2] 97 45 [2] 89 58 [2] 8b 59 [2] 90 5f [2] 8c 58 [2] 90 77 }

  condition:
    any of them
}