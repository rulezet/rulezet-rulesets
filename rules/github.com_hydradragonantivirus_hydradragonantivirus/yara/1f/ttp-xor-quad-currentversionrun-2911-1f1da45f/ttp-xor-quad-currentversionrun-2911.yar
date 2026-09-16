rule TTP_XOR_QUAD_CurrentVersionRun_2911 {
  strings:
    $key_2911 = { 7a 7e [2] 5e 70 [2] 75 5c [2] 5b 7e [2] 4f 65 [2] 40 7f [2] 5e 62 [2] 5c 63 [2] 47 65 [2] 5b 62 [2] 47 4d }

  condition:
    any of them
}