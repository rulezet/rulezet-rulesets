rule TTP_XOR_QUAD_CurrentVersionRun_3f19 {
  strings:
    $key_3f19 = { 6c 76 [2] 48 78 [2] 63 54 [2] 4d 76 [2] 59 6d [2] 56 77 [2] 48 6a [2] 4a 6b [2] 51 6d [2] 4d 6a [2] 51 45 }

  condition:
    any of them
}