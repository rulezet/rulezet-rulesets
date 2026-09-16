rule TTP_XOR_QUAD_CurrentVersionRun_0afd {
  strings:
    $key_0afd = { 59 92 [2] 7d 9c [2] 56 b0 [2] 78 92 [2] 6c 89 [2] 63 93 [2] 7d 8e [2] 7f 8f [2] 64 89 [2] 78 8e [2] 64 a1 }

  condition:
    any of them
}