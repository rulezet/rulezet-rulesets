rule TTP_XOR_QUAD_CurrentVersionRun_fe72 {
  strings:
    $key_fe72 = { ad 1d [2] 89 13 [2] a2 3f [2] 8c 1d [2] 98 06 [2] 97 1c [2] 89 01 [2] 8b 00 [2] 90 06 [2] 8c 01 [2] 90 2e }

  condition:
    any of them
}