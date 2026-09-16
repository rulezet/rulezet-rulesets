rule TTP_XOR_QUAD_CurrentVersionRun_5101 {
  strings:
    $key_5101 = { 02 6e [2] 26 60 [2] 0d 4c [2] 23 6e [2] 37 75 [2] 38 6f [2] 26 72 [2] 24 73 [2] 3f 75 [2] 23 72 [2] 3f 5d }

  condition:
    any of them
}