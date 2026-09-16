rule TTP_XOR_QUAD_CurrentVersionRun_132d {
  strings:
    $key_132d = { 40 42 [2] 64 4c [2] 4f 60 [2] 61 42 [2] 75 59 [2] 7a 43 [2] 64 5e [2] 66 5f [2] 7d 59 [2] 61 5e [2] 7d 71 }

  condition:
    any of them
}