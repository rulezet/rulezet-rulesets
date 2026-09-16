rule TTP_XOR_QUAD_CurrentVersionRun_1f21 {
  strings:
    $key_1f21 = { 4c 4e [2] 68 40 [2] 43 6c [2] 6d 4e [2] 79 55 [2] 76 4f [2] 68 52 [2] 6a 53 [2] 71 55 [2] 6d 52 [2] 71 7d }

  condition:
    any of them
}