rule TTP_XOR_QUAD_CurrentVersionRun_e207 {
  strings:
    $key_e207 = { b1 68 [2] 95 66 [2] be 4a [2] 90 68 [2] 84 73 [2] 8b 69 [2] 95 74 [2] 97 75 [2] 8c 73 [2] 90 74 [2] 8c 5b }

  condition:
    any of them
}