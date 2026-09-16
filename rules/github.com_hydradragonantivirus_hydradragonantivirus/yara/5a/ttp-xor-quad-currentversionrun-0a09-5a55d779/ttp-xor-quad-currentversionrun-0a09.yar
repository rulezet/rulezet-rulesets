rule TTP_XOR_QUAD_CurrentVersionRun_0a09 {
  strings:
    $key_0a09 = { 59 66 [2] 7d 68 [2] 56 44 [2] 78 66 [2] 6c 7d [2] 63 67 [2] 7d 7a [2] 7f 7b [2] 64 7d [2] 78 7a [2] 64 55 }

  condition:
    any of them
}