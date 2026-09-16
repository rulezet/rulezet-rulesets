rule TTP_XOR_QUAD_CurrentVersionRun_0f2d {
  strings:
    $key_0f2d = { 5c 42 [2] 78 4c [2] 53 60 [2] 7d 42 [2] 69 59 [2] 66 43 [2] 78 5e [2] 7a 5f [2] 61 59 [2] 7d 5e [2] 61 71 }

  condition:
    any of them
}