rule TTP_XOR_QUAD_CurrentVersionRun_fe76 {
  strings:
    $key_fe76 = { ad 19 [2] 89 17 [2] a2 3b [2] 8c 19 [2] 98 02 [2] 97 18 [2] 89 05 [2] 8b 04 [2] 90 02 [2] 8c 05 [2] 90 2a }

  condition:
    any of them
}