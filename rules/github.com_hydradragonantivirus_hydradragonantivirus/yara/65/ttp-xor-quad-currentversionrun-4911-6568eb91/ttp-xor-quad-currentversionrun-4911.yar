rule TTP_XOR_QUAD_CurrentVersionRun_4911 {
  strings:
    $key_4911 = { 1a 7e [2] 3e 70 [2] 15 5c [2] 3b 7e [2] 2f 65 [2] 20 7f [2] 3e 62 [2] 3c 63 [2] 27 65 [2] 3b 62 [2] 27 4d }

  condition:
    any of them
}