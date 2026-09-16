rule TTP_XOR_QUAD_CurrentVersionRun_4b0a {
  strings:
    $key_4b0a = { 18 65 [2] 3c 6b [2] 17 47 [2] 39 65 [2] 2d 7e [2] 22 64 [2] 3c 79 [2] 3e 78 [2] 25 7e [2] 39 79 [2] 25 56 }

  condition:
    any of them
}