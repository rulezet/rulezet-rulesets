rule TTP_XOR_QUAD_CurrentVersionRun_4411 {
  strings:
    $key_4411 = { 17 7e [2] 33 70 [2] 18 5c [2] 36 7e [2] 22 65 [2] 2d 7f [2] 33 62 [2] 31 63 [2] 2a 65 [2] 36 62 [2] 2a 4d }

  condition:
    any of them
}