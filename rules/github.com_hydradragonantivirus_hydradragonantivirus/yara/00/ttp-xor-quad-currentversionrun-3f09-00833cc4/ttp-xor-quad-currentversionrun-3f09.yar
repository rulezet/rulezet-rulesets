rule TTP_XOR_QUAD_CurrentVersionRun_3f09 {
  strings:
    $key_3f09 = { 6c 66 [2] 48 68 [2] 63 44 [2] 4d 66 [2] 59 7d [2] 56 67 [2] 48 7a [2] 4a 7b [2] 51 7d [2] 4d 7a [2] 51 55 }

  condition:
    any of them
}