rule TTP_XOR_QUAD_CurrentVersionRun_3af9 {
  strings:
    $key_3af9 = { 69 96 [2] 4d 98 [2] 66 b4 [2] 48 96 [2] 5c 8d [2] 53 97 [2] 4d 8a [2] 4f 8b [2] 54 8d [2] 48 8a [2] 54 a5 }

  condition:
    any of them
}