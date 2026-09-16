rule TTP_XOR_QUAD_CurrentVersionRun_2511 {
  strings:
    $key_2511 = { 76 7e [2] 52 70 [2] 79 5c [2] 57 7e [2] 43 65 [2] 4c 7f [2] 52 62 [2] 50 63 [2] 4b 65 [2] 57 62 [2] 4b 4d }

  condition:
    any of them
}