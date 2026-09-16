rule TTP_XOR_QUAD_CurrentVersionRun_5f11 {
  strings:
    $key_5f11 = { 0c 7e [2] 28 70 [2] 03 5c [2] 2d 7e [2] 39 65 [2] 36 7f [2] 28 62 [2] 2a 63 [2] 31 65 [2] 2d 62 [2] 31 4d }

  condition:
    any of them
}