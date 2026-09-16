rule TTP_XOR_QUAD_CurrentVersionRun_4f11 {
  strings:
    $key_4f11 = { 1c 7e [2] 38 70 [2] 13 5c [2] 3d 7e [2] 29 65 [2] 26 7f [2] 38 62 [2] 3a 63 [2] 21 65 [2] 3d 62 [2] 21 4d }

  condition:
    any of them
}