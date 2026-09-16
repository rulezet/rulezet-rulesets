rule TTP_XOR_QUAD_CurrentVersionRun_f938 {
  strings:
    $key_f938 = { aa 57 [2] 8e 59 [2] a5 75 [2] 8b 57 [2] 9f 4c [2] 90 56 [2] 8e 4b [2] 8c 4a [2] 97 4c [2] 8b 4b [2] 97 64 }

  condition:
    any of them
}