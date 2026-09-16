rule TTP_XOR_QUAD_CurrentVersionRun_1f0a {
  strings:
    $key_1f0a = { 4c 65 [2] 68 6b [2] 43 47 [2] 6d 65 [2] 79 7e [2] 76 64 [2] 68 79 [2] 6a 78 [2] 71 7e [2] 6d 79 [2] 71 56 }

  condition:
    any of them
}