rule TTP_XOR_QUAD_CurrentVersionRun_6551 {
  strings:
    $key_6551 = { 36 3e [2] 12 30 [2] 39 1c [2] 17 3e [2] 03 25 [2] 0c 3f [2] 12 22 [2] 10 23 [2] 0b 25 [2] 17 22 [2] 0b 0d }

  condition:
    any of them
}