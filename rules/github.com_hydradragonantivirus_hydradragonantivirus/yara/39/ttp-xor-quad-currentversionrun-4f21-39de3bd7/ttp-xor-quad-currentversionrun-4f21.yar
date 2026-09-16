rule TTP_XOR_QUAD_CurrentVersionRun_4f21 {
  strings:
    $key_4f21 = { 1c 4e [2] 38 40 [2] 13 6c [2] 3d 4e [2] 29 55 [2] 26 4f [2] 38 52 [2] 3a 53 [2] 21 55 [2] 3d 52 [2] 21 7d }

  condition:
    any of them
}