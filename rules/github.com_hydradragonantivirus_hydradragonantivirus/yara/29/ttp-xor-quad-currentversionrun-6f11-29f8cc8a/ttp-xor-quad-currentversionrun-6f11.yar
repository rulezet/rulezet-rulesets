rule TTP_XOR_QUAD_CurrentVersionRun_6f11 {
  strings:
    $key_6f11 = { 3c 7e [2] 18 70 [2] 33 5c [2] 1d 7e [2] 09 65 [2] 06 7f [2] 18 62 [2] 1a 63 [2] 01 65 [2] 1d 62 [2] 01 4d }

  condition:
    any of them
}