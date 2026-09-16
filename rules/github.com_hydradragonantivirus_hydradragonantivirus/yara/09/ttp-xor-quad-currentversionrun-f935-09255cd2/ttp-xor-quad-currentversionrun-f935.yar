rule TTP_XOR_QUAD_CurrentVersionRun_f935 {
  strings:
    $key_f935 = { aa 5a [2] 8e 54 [2] a5 78 [2] 8b 5a [2] 9f 41 [2] 90 5b [2] 8e 46 [2] 8c 47 [2] 97 41 [2] 8b 46 [2] 97 69 }

  condition:
    any of them
}