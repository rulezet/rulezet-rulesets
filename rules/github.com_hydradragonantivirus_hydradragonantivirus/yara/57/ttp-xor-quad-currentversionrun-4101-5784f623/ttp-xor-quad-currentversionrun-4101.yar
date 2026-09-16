rule TTP_XOR_QUAD_CurrentVersionRun_4101 {
  strings:
    $key_4101 = { 12 6e [2] 36 60 [2] 1d 4c [2] 33 6e [2] 27 75 [2] 28 6f [2] 36 72 [2] 34 73 [2] 2f 75 [2] 33 72 [2] 2f 5d }

  condition:
    any of them
}