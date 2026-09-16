rule TTP_XOR_QUAD_CurrentVersionRun_f905 {
  strings:
    $key_f905 = { aa 6a [2] 8e 64 [2] a5 48 [2] 8b 6a [2] 9f 71 [2] 90 6b [2] 8e 76 [2] 8c 77 [2] 97 71 [2] 8b 76 [2] 97 59 }

  condition:
    any of them
}