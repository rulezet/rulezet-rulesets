rule TTP_XOR_QUAD_CurrentVersionRun_3859 {
  strings:
    $key_3859 = { 6b 36 [2] 4f 38 [2] 64 14 [2] 4a 36 [2] 5e 2d [2] 51 37 [2] 4f 2a [2] 4d 2b [2] 56 2d [2] 4a 2a [2] 56 05 }

  condition:
    any of them
}