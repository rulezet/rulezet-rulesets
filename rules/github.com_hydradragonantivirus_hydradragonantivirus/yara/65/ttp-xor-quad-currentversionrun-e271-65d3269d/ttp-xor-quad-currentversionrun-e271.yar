rule TTP_XOR_QUAD_CurrentVersionRun_e271 {
  strings:
    $key_e271 = { b1 1e [2] 95 10 [2] be 3c [2] 90 1e [2] 84 05 [2] 8b 1f [2] 95 02 [2] 97 03 [2] 8c 05 [2] 90 02 [2] 8c 2d }

  condition:
    any of them
}