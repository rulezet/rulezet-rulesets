rule TTP_XOR_QUAD_CurrentVersionRun_3f56 {
  strings:
    $key_3f56 = { 6c 39 [2] 48 37 [2] 63 1b [2] 4d 39 [2] 59 22 [2] 56 38 [2] 48 25 [2] 4a 24 [2] 51 22 [2] 4d 25 [2] 51 0a }

  condition:
    any of them
}