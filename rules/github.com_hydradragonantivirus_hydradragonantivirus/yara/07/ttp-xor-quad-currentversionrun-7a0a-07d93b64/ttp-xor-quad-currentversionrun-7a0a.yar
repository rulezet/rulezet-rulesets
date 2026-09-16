rule TTP_XOR_QUAD_CurrentVersionRun_7a0a {
  strings:
    $key_7a0a = { 29 65 [2] 0d 6b [2] 26 47 [2] 08 65 [2] 1c 7e [2] 13 64 [2] 0d 79 [2] 0f 78 [2] 14 7e [2] 08 79 [2] 14 56 }

  condition:
    any of them
}