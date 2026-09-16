rule TTP_XOR_QUAD_CurrentVersionRun_f97e {
  strings:
    $key_f97e = { aa 11 [2] 8e 1f [2] a5 33 [2] 8b 11 [2] 9f 0a [2] 90 10 [2] 8e 0d [2] 8c 0c [2] 97 0a [2] 8b 0d [2] 97 22 }

  condition:
    any of them
}