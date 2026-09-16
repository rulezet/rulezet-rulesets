rule TTP_XOR_QUAD_CurrentVersionRun_2f11 {
  strings:
    $key_2f11 = { 7c 7e [2] 58 70 [2] 73 5c [2] 5d 7e [2] 49 65 [2] 46 7f [2] 58 62 [2] 5a 63 [2] 41 65 [2] 5d 62 [2] 41 4d }

  condition:
    any of them
}