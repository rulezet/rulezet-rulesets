rule TTP_XOR_QUAD_CurrentVersionRun_2647 {
  strings:
    $key_2647 = { 75 28 [2] 51 26 [2] 7a 0a [2] 54 28 [2] 40 33 [2] 4f 29 [2] 51 34 [2] 53 35 [2] 48 33 [2] 54 34 [2] 48 1b }

  condition:
    any of them
}