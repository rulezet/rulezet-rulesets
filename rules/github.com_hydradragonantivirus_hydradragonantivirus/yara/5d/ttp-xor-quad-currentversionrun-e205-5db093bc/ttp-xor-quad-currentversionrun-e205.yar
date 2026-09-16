rule TTP_XOR_QUAD_CurrentVersionRun_e205 {
  strings:
    $key_e205 = { b1 6a [2] 95 64 [2] be 48 [2] 90 6a [2] 84 71 [2] 8b 6b [2] 95 76 [2] 97 77 [2] 8c 71 [2] 90 76 [2] 8c 59 }

  condition:
    any of them
}