rule TTP_XOR_QUAD_CurrentVersionRun_7a71 {
  strings:
    $key_7a71 = { 29 1e [2] 0d 10 [2] 26 3c [2] 08 1e [2] 1c 05 [2] 13 1f [2] 0d 02 [2] 0f 03 [2] 14 05 [2] 08 02 [2] 14 2d }

  condition:
    any of them
}