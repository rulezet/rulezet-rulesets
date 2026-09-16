rule TTP_XOR_QUAD_CurrentVersionRun_3911 {
  strings:
    $key_3911 = { 6a 7e [2] 4e 70 [2] 65 5c [2] 4b 7e [2] 5f 65 [2] 50 7f [2] 4e 62 [2] 4c 63 [2] 57 65 [2] 4b 62 [2] 57 4d }

  condition:
    any of them
}