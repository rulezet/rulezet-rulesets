rule TTP_XOR_QUAD_CurrentVersionRun_2521 {
  strings:
    $key_2521 = { 76 4e [2] 52 40 [2] 79 6c [2] 57 4e [2] 43 55 [2] 4c 4f [2] 52 52 [2] 50 53 [2] 4b 55 [2] 57 52 [2] 4b 7d }

  condition:
    any of them
}