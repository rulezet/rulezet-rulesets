rule TTP_XOR_QUAD_CurrentVersionRun_6511 {
  strings:
    $key_6511 = { 36 7e [2] 12 70 [2] 39 5c [2] 17 7e [2] 03 65 [2] 0c 7f [2] 12 62 [2] 10 63 [2] 0b 65 [2] 17 62 [2] 0b 4d }

  condition:
    any of them
}