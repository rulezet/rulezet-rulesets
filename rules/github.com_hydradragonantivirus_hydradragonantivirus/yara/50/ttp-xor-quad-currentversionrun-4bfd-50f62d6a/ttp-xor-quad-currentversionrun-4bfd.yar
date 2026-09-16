rule TTP_XOR_QUAD_CurrentVersionRun_4bfd {
  strings:
    $key_4bfd = { 18 92 [2] 3c 9c [2] 17 b0 [2] 39 92 [2] 2d 89 [2] 22 93 [2] 3c 8e [2] 3e 8f [2] 25 89 [2] 39 8e [2] 25 a1 }

  condition:
    any of them
}