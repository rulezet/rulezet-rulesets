rule TTP_XOR_QUAD_CurrentVersionRun_7ae4 {
  strings:
    $key_7ae4 = { 29 8b [2] 0d 85 [2] 26 a9 [2] 08 8b [2] 1c 90 [2] 13 8a [2] 0d 97 [2] 0f 96 [2] 14 90 [2] 08 97 [2] 14 b8 }

  condition:
    any of them
}