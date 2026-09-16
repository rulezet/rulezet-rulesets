rule TTP_XOR_QUAD_CurrentVersionRun_f939 {
  strings:
    $key_f939 = { aa 56 [2] 8e 58 [2] a5 74 [2] 8b 56 [2] 9f 4d [2] 90 57 [2] 8e 4a [2] 8c 4b [2] 97 4d [2] 8b 4a [2] 97 65 }

  condition:
    any of them
}