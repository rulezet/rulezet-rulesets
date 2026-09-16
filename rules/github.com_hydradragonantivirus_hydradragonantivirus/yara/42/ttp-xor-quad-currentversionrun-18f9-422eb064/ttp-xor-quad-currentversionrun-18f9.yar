rule TTP_XOR_QUAD_CurrentVersionRun_18f9 {
  strings:
    $key_18f9 = { 4b 96 [2] 6f 98 [2] 44 b4 [2] 6a 96 [2] 7e 8d [2] 71 97 [2] 6f 8a [2] 6d 8b [2] 76 8d [2] 6a 8a [2] 76 a5 }

  condition:
    any of them
}