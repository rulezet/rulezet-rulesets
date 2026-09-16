rule TTP_XOR_QUAD_CurrentVersionRun_e225 {
  strings:
    $key_e225 = { b1 4a [2] 95 44 [2] be 68 [2] 90 4a [2] 84 51 [2] 8b 4b [2] 95 56 [2] 97 57 [2] 8c 51 [2] 90 56 [2] 8c 79 }

  condition:
    any of them
}