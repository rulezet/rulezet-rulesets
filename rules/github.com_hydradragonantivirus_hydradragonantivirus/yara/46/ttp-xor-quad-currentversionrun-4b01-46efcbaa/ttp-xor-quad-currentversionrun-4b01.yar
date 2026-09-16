rule TTP_XOR_QUAD_CurrentVersionRun_4b01 {
  strings:
    $key_4b01 = { 18 6e [2] 3c 60 [2] 17 4c [2] 39 6e [2] 2d 75 [2] 22 6f [2] 3c 72 [2] 3e 73 [2] 25 75 [2] 39 72 [2] 25 5d }

  condition:
    any of them
}