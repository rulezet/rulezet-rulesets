rule TTP_XOR_QUAD_CurrentVersionRun_030a {
  strings:
    $key_030a = { 50 65 [2] 74 6b [2] 5f 47 [2] 71 65 [2] 65 7e [2] 6a 64 [2] 74 79 [2] 76 78 [2] 6d 7e [2] 71 79 [2] 6d 56 }

  condition:
    any of them
}