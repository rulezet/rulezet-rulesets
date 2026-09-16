rule TTP_XOR_QUAD_CurrentVersionRun_3bfd {
  strings:
    $key_3bfd = { 68 92 [2] 4c 9c [2] 67 b0 [2] 49 92 [2] 5d 89 [2] 52 93 [2] 4c 8e [2] 4e 8f [2] 55 89 [2] 49 8e [2] 55 a1 }

  condition:
    any of them
}