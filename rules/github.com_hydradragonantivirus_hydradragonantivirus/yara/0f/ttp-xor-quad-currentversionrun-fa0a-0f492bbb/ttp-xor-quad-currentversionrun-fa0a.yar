rule TTP_XOR_QUAD_CurrentVersionRun_fa0a {
  strings:
    $key_fa0a = { a9 65 [2] 8d 6b [2] a6 47 [2] 88 65 [2] 9c 7e [2] 93 64 [2] 8d 79 [2] 8f 78 [2] 94 7e [2] 88 79 [2] 94 56 }

  condition:
    any of them
}