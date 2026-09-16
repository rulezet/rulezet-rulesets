rule TTP_XOR_QUAD_CurrentVersionRun_f945 {
  strings:
    $key_f945 = { aa 2a [2] 8e 24 [2] a5 08 [2] 8b 2a [2] 9f 31 [2] 90 2b [2] 8e 36 [2] 8c 37 [2] 97 31 [2] 8b 36 [2] 97 19 }

  condition:
    any of them
}