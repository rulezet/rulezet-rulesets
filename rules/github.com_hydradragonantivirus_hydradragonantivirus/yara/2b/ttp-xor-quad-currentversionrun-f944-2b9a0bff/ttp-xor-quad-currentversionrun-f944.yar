rule TTP_XOR_QUAD_CurrentVersionRun_f944 {
  strings:
    $key_f944 = { aa 2b [2] 8e 25 [2] a5 09 [2] 8b 2b [2] 9f 30 [2] 90 2a [2] 8e 37 [2] 8c 36 [2] 97 30 [2] 8b 37 [2] 97 18 }

  condition:
    any of them
}