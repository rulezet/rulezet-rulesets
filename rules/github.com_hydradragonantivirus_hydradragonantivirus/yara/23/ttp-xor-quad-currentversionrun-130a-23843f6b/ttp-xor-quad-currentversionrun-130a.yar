rule TTP_XOR_QUAD_CurrentVersionRun_130a {
  strings:
    $key_130a = { 40 65 [2] 64 6b [2] 4f 47 [2] 61 65 [2] 75 7e [2] 7a 64 [2] 64 79 [2] 66 78 [2] 7d 7e [2] 61 79 [2] 7d 56 }

  condition:
    any of them
}