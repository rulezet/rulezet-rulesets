rule TTP_XOR_QUAD_CurrentVersionRun_e259 {
  strings:
    $key_e259 = { b1 36 [2] 95 38 [2] be 14 [2] 90 36 [2] 84 2d [2] 8b 37 [2] 95 2a [2] 97 2b [2] 8c 2d [2] 90 2a [2] 8c 05 }

  condition:
    any of them
}