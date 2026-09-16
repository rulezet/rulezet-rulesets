rule TTP_XOR_QUAD_CurrentVersionRun_fe49 {
  strings:
    $key_fe49 = { ad 26 [2] 89 28 [2] a2 04 [2] 8c 26 [2] 98 3d [2] 97 27 [2] 89 3a [2] 8b 3b [2] 90 3d [2] 8c 3a [2] 90 15 }

  condition:
    any of them
}