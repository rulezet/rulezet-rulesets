rule TTP_XOR_QUAD_CurrentVersionRun_0ae5 {
  strings:
    $key_0ae5 = { 59 8a [2] 7d 84 [2] 56 a8 [2] 78 8a [2] 6c 91 [2] 63 8b [2] 7d 96 [2] 7f 97 [2] 64 91 [2] 78 96 [2] 64 b9 }

  condition:
    any of them
}