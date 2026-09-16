rule TTP_XOR_QUAD_CurrentVersionRun_04fc {
  strings:
    $key_04fc = { 57 93 [2] 73 9d [2] 58 b1 [2] 76 93 [2] 62 88 [2] 6d 92 [2] 73 8f [2] 71 8e [2] 6a 88 [2] 76 8f [2] 6a a0 }

  condition:
    any of them
}