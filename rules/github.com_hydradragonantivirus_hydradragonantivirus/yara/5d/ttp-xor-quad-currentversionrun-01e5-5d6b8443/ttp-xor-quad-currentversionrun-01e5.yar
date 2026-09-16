rule TTP_XOR_QUAD_CurrentVersionRun_01e5 {
  strings:
    $key_01e5 = { 52 8a [2] 76 84 [2] 5d a8 [2] 73 8a [2] 67 91 [2] 68 8b [2] 76 96 [2] 74 97 [2] 6f 91 [2] 73 96 [2] 6f b9 }

  condition:
    any of them
}