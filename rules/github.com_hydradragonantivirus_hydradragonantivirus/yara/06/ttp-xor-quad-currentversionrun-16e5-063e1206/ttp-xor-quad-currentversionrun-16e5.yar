rule TTP_XOR_QUAD_CurrentVersionRun_16e5 {
  strings:
    $key_16e5 = { 45 8a [2] 61 84 [2] 4a a8 [2] 64 8a [2] 70 91 [2] 7f 8b [2] 61 96 [2] 63 97 [2] 78 91 [2] 64 96 [2] 78 b9 }

  condition:
    any of them
}