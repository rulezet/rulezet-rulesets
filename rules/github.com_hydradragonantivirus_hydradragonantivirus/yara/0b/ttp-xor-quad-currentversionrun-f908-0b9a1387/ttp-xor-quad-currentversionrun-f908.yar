rule TTP_XOR_QUAD_CurrentVersionRun_f908 {
  strings:
    $key_f908 = { aa 67 [2] 8e 69 [2] a5 45 [2] 8b 67 [2] 9f 7c [2] 90 66 [2] 8e 7b [2] 8c 7a [2] 97 7c [2] 8b 7b [2] 97 54 }

  condition:
    any of them
}