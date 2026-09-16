rule TTP_XOR_QUAD_CurrentVersionRun_e255 {
  strings:
    $key_e255 = { b1 3a [2] 95 34 [2] be 18 [2] 90 3a [2] 84 21 [2] 8b 3b [2] 95 26 [2] 97 27 [2] 8c 21 [2] 90 26 [2] 8c 09 }

  condition:
    any of them
}