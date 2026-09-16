rule TTP_XOR_QUAD_CurrentVersionRun_4b03 {
  strings:
    $key_4b03 = { 18 6c [2] 3c 62 [2] 17 4e [2] 39 6c [2] 2d 77 [2] 22 6d [2] 3c 70 [2] 3e 71 [2] 25 77 [2] 39 70 [2] 25 5f }

  condition:
    any of them
}