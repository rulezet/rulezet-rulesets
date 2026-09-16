rule TTP_XOR_QUAD_CurrentVersionRun_f965 {
  strings:
    $key_f965 = { aa 0a [2] 8e 04 [2] a5 28 [2] 8b 0a [2] 9f 11 [2] 90 0b [2] 8e 16 [2] 8c 17 [2] 97 11 [2] 8b 16 [2] 97 39 }

  condition:
    any of them
}