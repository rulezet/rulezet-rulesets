rule TTP_XOR_QUAD_CurrentVersionRun_3f24 {
  strings:
    $key_3f24 = { 6c 4b [2] 48 45 [2] 63 69 [2] 4d 4b [2] 59 50 [2] 56 4a [2] 48 57 [2] 4a 56 [2] 51 50 [2] 4d 57 [2] 51 78 }

  condition:
    any of them
}