rule TTP_XOR_QUAD_CurrentVersionRun_53fc {
  strings:
    $key_53fc = { 00 93 [2] 24 9d [2] 0f b1 [2] 21 93 [2] 35 88 [2] 3a 92 [2] 24 8f [2] 26 8e [2] 3d 88 [2] 21 8f [2] 3d a0 }

  condition:
    any of them
}