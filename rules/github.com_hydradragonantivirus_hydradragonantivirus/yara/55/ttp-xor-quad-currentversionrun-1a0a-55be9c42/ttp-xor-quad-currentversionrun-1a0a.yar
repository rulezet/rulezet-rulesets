rule TTP_XOR_QUAD_CurrentVersionRun_1a0a {
  strings:
    $key_1a0a = { 49 65 [2] 6d 6b [2] 46 47 [2] 68 65 [2] 7c 7e [2] 73 64 [2] 6d 79 [2] 6f 78 [2] 74 7e [2] 68 79 [2] 74 56 }

  condition:
    any of them
}