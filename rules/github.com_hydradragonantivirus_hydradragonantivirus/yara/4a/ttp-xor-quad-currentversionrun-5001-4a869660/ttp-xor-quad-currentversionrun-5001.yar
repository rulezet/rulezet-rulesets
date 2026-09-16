rule TTP_XOR_QUAD_CurrentVersionRun_5001 {
  strings:
    $key_5001 = { 03 6e [2] 27 60 [2] 0c 4c [2] 22 6e [2] 36 75 [2] 39 6f [2] 27 72 [2] 25 73 [2] 3e 75 [2] 22 72 [2] 3e 5d }

  condition:
    any of them
}