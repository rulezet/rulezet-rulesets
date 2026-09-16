rule TTP_XOR_QUAD_CurrentVersionRun_3403 {
  strings:
    $key_3403 = { 67 6c [2] 43 62 [2] 68 4e [2] 46 6c [2] 52 77 [2] 5d 6d [2] 43 70 [2] 41 71 [2] 5a 77 [2] 46 70 [2] 5a 5f }

  condition:
    any of them
}