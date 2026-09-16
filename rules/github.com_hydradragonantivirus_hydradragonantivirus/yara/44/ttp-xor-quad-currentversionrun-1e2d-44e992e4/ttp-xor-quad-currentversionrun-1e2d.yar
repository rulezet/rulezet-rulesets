rule TTP_XOR_QUAD_CurrentVersionRun_1e2d {
  strings:
    $key_1e2d = { 4d 42 [2] 69 4c [2] 42 60 [2] 6c 42 [2] 78 59 [2] 77 43 [2] 69 5e [2] 6b 5f [2] 70 59 [2] 6c 5e [2] 70 71 }

  condition:
    any of them
}