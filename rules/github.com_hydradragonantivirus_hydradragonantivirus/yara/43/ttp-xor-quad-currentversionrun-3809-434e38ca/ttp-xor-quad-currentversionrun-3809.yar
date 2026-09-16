rule TTP_XOR_QUAD_CurrentVersionRun_3809 {
  strings:
    $key_3809 = { 6b 66 [2] 4f 68 [2] 64 44 [2] 4a 66 [2] 5e 7d [2] 51 67 [2] 4f 7a [2] 4d 7b [2] 56 7d [2] 4a 7a [2] 56 55 }

  condition:
    any of them
}