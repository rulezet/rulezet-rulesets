rule TTP_XOR_QUAD_CurrentVersionRun_fe06 {
  strings:
    $key_fe06 = { ad 69 [2] 89 67 [2] a2 4b [2] 8c 69 [2] 98 72 [2] 97 68 [2] 89 75 [2] 8b 74 [2] 90 72 [2] 8c 75 [2] 90 5a }

  condition:
    any of them
}