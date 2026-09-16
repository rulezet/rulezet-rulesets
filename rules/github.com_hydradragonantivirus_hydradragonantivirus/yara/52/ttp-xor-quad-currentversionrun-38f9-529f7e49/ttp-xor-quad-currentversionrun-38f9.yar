rule TTP_XOR_QUAD_CurrentVersionRun_38f9 {
  strings:
    $key_38f9 = { 6b 96 [2] 4f 98 [2] 64 b4 [2] 4a 96 [2] 5e 8d [2] 51 97 [2] 4f 8a [2] 4d 8b [2] 56 8d [2] 4a 8a [2] 56 a5 }

  condition:
    any of them
}