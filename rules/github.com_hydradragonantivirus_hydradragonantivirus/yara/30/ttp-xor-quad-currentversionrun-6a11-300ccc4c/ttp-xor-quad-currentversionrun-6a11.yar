rule TTP_XOR_QUAD_CurrentVersionRun_6a11 {
  strings:
    $key_6a11 = { 39 7e [2] 1d 70 [2] 36 5c [2] 18 7e [2] 0c 65 [2] 03 7f [2] 1d 62 [2] 1f 63 [2] 04 65 [2] 18 62 [2] 04 4d }

  condition:
    any of them
}