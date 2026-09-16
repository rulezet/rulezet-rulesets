rule TTP_XOR_QUAD_CurrentVersionRun_5f21 {
  strings:
    $key_5f21 = { 0c 4e [2] 28 40 [2] 03 6c [2] 2d 4e [2] 39 55 [2] 36 4f [2] 28 52 [2] 2a 53 [2] 31 55 [2] 2d 52 [2] 31 7d }

  condition:
    any of them
}