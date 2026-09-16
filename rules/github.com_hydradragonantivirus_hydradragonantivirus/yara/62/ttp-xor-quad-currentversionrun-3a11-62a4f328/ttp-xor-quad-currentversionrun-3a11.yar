rule TTP_XOR_QUAD_CurrentVersionRun_3a11 {
  strings:
    $key_3a11 = { 69 7e [2] 4d 70 [2] 66 5c [2] 48 7e [2] 5c 65 [2] 53 7f [2] 4d 62 [2] 4f 63 [2] 54 65 [2] 48 62 [2] 54 4d }

  condition:
    any of them
}