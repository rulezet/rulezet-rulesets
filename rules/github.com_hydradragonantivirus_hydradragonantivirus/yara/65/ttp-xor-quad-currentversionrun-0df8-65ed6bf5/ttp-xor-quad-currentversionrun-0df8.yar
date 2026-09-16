rule TTP_XOR_QUAD_CurrentVersionRun_0df8 {
  strings:
    $key_0df8 = { 5e 97 [2] 7a 99 [2] 51 b5 [2] 7f 97 [2] 6b 8c [2] 64 96 [2] 7a 8b [2] 78 8a [2] 63 8c [2] 7f 8b [2] 63 a4 }

  condition:
    any of them
}