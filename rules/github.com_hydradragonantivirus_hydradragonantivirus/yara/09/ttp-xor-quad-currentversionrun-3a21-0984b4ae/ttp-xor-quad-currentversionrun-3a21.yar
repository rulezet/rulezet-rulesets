rule TTP_XOR_QUAD_CurrentVersionRun_3a21 {
  strings:
    $key_3a21 = { 69 4e [2] 4d 40 [2] 66 6c [2] 48 4e [2] 5c 55 [2] 53 4f [2] 4d 52 [2] 4f 53 [2] 54 55 [2] 48 52 [2] 54 7d }

  condition:
    any of them
}