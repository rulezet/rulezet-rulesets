rule TTP_XOR_QUAD_CurrentVersionRun_03f9 {
  strings:
    $key_03f9 = { 50 96 [2] 74 98 [2] 5f b4 [2] 71 96 [2] 65 8d [2] 6a 97 [2] 74 8a [2] 76 8b [2] 6d 8d [2] 71 8a [2] 6d a5 }

  condition:
    any of them
}