rule TTP_XOR_QUAD_CurrentVersionRun_0f01 {
  strings:
    $key_0f01 = { 5c 6e [2] 78 60 [2] 53 4c [2] 7d 6e [2] 69 75 [2] 66 6f [2] 78 72 [2] 7a 73 [2] 61 75 [2] 7d 72 [2] 61 5d }

  condition:
    any of them
}