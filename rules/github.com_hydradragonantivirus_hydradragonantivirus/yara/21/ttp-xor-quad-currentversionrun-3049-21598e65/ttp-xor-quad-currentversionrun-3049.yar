rule TTP_XOR_QUAD_CurrentVersionRun_3049 {
  strings:
    $key_3049 = { 63 26 [2] 47 28 [2] 6c 04 [2] 42 26 [2] 56 3d [2] 59 27 [2] 47 3a [2] 45 3b [2] 5e 3d [2] 42 3a [2] 5e 15 }

  condition:
    any of them
}