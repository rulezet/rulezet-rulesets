rule TTP_XOR_QUAD_CurrentVersionRun_f927 {
  strings:
    $key_f927 = { aa 48 [2] 8e 46 [2] a5 6a [2] 8b 48 [2] 9f 53 [2] 90 49 [2] 8e 54 [2] 8c 55 [2] 97 53 [2] 8b 54 [2] 97 7b }

  condition:
    any of them
}