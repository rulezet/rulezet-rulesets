rule TTP_XOR_QUAD_CurrentVersionRun_7a01 {
  strings:
    $key_7a01 = { 29 6e [2] 0d 60 [2] 26 4c [2] 08 6e [2] 1c 75 [2] 13 6f [2] 0d 72 [2] 0f 73 [2] 14 75 [2] 08 72 [2] 14 5d }

  condition:
    any of them
}