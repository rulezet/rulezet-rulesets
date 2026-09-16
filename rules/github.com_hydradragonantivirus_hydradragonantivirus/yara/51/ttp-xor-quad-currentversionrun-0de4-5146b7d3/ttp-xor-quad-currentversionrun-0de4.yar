rule TTP_XOR_QUAD_CurrentVersionRun_0de4 {
  strings:
    $key_0de4 = { 5e 8b [2] 7a 85 [2] 51 a9 [2] 7f 8b [2] 6b 90 [2] 64 8a [2] 7a 97 [2] 78 96 [2] 63 90 [2] 7f 97 [2] 63 b8 }

  condition:
    any of them
}