rule TTP_XOR_QUAD_CurrentVersionRun_48e5 {
  strings:
    $key_48e5 = { 1b 8a [2] 3f 84 [2] 14 a8 [2] 3a 8a [2] 2e 91 [2] 21 8b [2] 3f 96 [2] 3d 97 [2] 26 91 [2] 3a 96 [2] 26 b9 }

  condition:
    any of them
}