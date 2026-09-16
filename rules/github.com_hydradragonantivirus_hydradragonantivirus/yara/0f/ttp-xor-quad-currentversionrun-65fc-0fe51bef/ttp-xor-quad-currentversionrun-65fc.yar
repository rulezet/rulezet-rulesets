rule TTP_XOR_QUAD_CurrentVersionRun_65fc {
  strings:
    $key_65fc = { 36 93 [2] 12 9d [2] 39 b1 [2] 17 93 [2] 03 88 [2] 0c 92 [2] 12 8f [2] 10 8e [2] 0b 88 [2] 17 8f [2] 0b a0 }

  condition:
    any of them
}