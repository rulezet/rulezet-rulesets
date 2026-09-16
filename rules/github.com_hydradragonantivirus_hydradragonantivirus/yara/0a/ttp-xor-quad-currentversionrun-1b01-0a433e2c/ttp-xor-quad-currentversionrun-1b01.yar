rule TTP_XOR_QUAD_CurrentVersionRun_1b01 {
  strings:
    $key_1b01 = { 48 6e [2] 6c 60 [2] 47 4c [2] 69 6e [2] 7d 75 [2] 72 6f [2] 6c 72 [2] 6e 73 [2] 75 75 [2] 69 72 [2] 75 5d }

  condition:
    any of them
}