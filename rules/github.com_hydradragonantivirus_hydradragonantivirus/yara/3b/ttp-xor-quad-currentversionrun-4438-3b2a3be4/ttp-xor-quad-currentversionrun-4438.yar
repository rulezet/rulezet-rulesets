rule TTP_XOR_QUAD_CurrentVersionRun_4438 {
  strings:
    $key_4438 = { 17 57 [2] 33 59 [2] 18 75 [2] 36 57 [2] 22 4c [2] 2d 56 [2] 33 4b [2] 31 4a [2] 2a 4c [2] 36 4b [2] 2a 64 }

  condition:
    any of them
}