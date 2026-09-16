rule TTP_XOR_QUAD_CurrentVersionRun_0df9 {
  strings:
    $key_0df9 = { 5e 96 [2] 7a 98 [2] 51 b4 [2] 7f 96 [2] 6b 8d [2] 64 97 [2] 7a 8a [2] 78 8b [2] 63 8d [2] 7f 8a [2] 63 a5 }

  condition:
    any of them
}