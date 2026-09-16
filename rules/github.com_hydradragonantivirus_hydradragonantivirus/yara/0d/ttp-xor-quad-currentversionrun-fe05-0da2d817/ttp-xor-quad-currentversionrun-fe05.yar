rule TTP_XOR_QUAD_CurrentVersionRun_fe05 {
  strings:
    $key_fe05 = { ad 6a [2] 89 64 [2] a2 48 [2] 8c 6a [2] 98 71 [2] 97 6b [2] 89 76 [2] 8b 77 [2] 90 71 [2] 8c 76 [2] 90 59 }

  condition:
    any of them
}