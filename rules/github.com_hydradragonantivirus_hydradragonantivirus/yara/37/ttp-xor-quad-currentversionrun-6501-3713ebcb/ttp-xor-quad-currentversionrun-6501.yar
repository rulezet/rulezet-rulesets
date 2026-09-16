rule TTP_XOR_QUAD_CurrentVersionRun_6501 {
  strings:
    $key_6501 = { 36 6e [2] 12 60 [2] 39 4c [2] 17 6e [2] 03 75 [2] 0c 6f [2] 12 72 [2] 10 73 [2] 0b 75 [2] 17 72 [2] 0b 5d }

  condition:
    any of them
}