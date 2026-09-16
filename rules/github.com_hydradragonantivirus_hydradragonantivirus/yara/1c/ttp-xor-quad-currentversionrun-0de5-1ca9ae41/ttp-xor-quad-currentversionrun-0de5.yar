rule TTP_XOR_QUAD_CurrentVersionRun_0de5 {
  strings:
    $key_0de5 = { 5e 8a [2] 7a 84 [2] 51 a8 [2] 7f 8a [2] 6b 91 [2] 64 8b [2] 7a 96 [2] 78 97 [2] 63 91 [2] 7f 96 [2] 63 b9 }

  condition:
    any of them
}