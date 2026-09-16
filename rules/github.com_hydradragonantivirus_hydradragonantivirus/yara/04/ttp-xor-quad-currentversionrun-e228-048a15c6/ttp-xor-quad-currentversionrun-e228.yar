rule TTP_XOR_QUAD_CurrentVersionRun_e228 {
  strings:
    $key_e228 = { b1 47 [2] 95 49 [2] be 65 [2] 90 47 [2] 84 5c [2] 8b 46 [2] 95 5b [2] 97 5a [2] 8c 5c [2] 90 5b [2] 8c 74 }

  condition:
    any of them
}