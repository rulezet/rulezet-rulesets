rule TTP_XOR_QUAD_CurrentVersionRun_3f38 {
  strings:
    $key_3f38 = { 6c 57 [2] 48 59 [2] 63 75 [2] 4d 57 [2] 59 4c [2] 56 56 [2] 48 4b [2] 4a 4a [2] 51 4c [2] 4d 4b [2] 51 64 }

  condition:
    any of them
}