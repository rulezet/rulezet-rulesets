rule TTP_XOR_QUAD_CurrentVersionRun_2211 {
  strings:
    $key_2211 = { 71 7e [2] 55 70 [2] 7e 5c [2] 50 7e [2] 44 65 [2] 4b 7f [2] 55 62 [2] 57 63 [2] 4c 65 [2] 50 62 [2] 4c 4d }

  condition:
    any of them
}