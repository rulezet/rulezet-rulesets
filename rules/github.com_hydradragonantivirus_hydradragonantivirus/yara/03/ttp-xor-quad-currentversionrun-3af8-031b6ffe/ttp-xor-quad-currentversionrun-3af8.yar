rule TTP_XOR_QUAD_CurrentVersionRun_3af8 {
  strings:
    $key_3af8 = { 69 97 [2] 4d 99 [2] 66 b5 [2] 48 97 [2] 5c 8c [2] 53 96 [2] 4d 8b [2] 4f 8a [2] 54 8c [2] 48 8b [2] 54 a4 }

  condition:
    any of them
}