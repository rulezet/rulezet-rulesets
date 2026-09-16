rule TTP_XOR_QUAD_CurrentVersionRun_48f9 {
  strings:
    $key_48f9 = { 1b 96 [2] 3f 98 [2] 14 b4 [2] 3a 96 [2] 2e 8d [2] 21 97 [2] 3f 8a [2] 3d 8b [2] 26 8d [2] 3a 8a [2] 26 a5 }

  condition:
    any of them
}