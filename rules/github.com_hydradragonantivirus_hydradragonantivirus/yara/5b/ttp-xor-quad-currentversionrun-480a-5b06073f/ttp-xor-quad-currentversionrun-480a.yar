rule TTP_XOR_QUAD_CurrentVersionRun_480a {
  strings:
    $key_480a = { 1b 65 [2] 3f 6b [2] 14 47 [2] 3a 65 [2] 2e 7e [2] 21 64 [2] 3f 79 [2] 3d 78 [2] 26 7e [2] 3a 79 [2] 26 56 }

  condition:
    any of them
}