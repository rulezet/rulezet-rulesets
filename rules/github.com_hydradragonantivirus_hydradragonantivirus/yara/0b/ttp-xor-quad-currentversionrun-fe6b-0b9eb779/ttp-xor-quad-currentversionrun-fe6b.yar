rule TTP_XOR_QUAD_CurrentVersionRun_fe6b {
  strings:
    $key_fe6b = { ad 04 [2] 89 0a [2] a2 26 [2] 8c 04 [2] 98 1f [2] 97 05 [2] 89 18 [2] 8b 19 [2] 90 1f [2] 8c 18 [2] 90 37 }

  condition:
    any of them
}