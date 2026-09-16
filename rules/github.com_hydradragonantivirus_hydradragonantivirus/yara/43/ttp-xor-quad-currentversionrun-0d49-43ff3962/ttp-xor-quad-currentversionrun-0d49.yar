rule TTP_XOR_QUAD_CurrentVersionRun_0d49 {
  strings:
    $key_0d49 = { 5e 26 [2] 7a 28 [2] 51 04 [2] 7f 26 [2] 6b 3d [2] 64 27 [2] 7a 3a [2] 78 3b [2] 63 3d [2] 7f 3a [2] 63 15 }

  condition:
    any of them
}