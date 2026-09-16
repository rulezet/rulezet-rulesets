rule TTP_XOR_QUAD_CurrentVersionRun_4b11 {
  strings:
    $key_4b11 = { 18 7e [2] 3c 70 [2] 17 5c [2] 39 7e [2] 2d 65 [2] 22 7f [2] 3c 62 [2] 3e 63 [2] 25 65 [2] 39 62 [2] 25 4d }

  condition:
    any of them
}