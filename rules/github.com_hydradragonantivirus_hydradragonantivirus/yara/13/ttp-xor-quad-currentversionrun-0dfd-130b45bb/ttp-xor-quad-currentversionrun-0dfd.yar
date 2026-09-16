rule TTP_XOR_QUAD_CurrentVersionRun_0dfd {
  strings:
    $key_0dfd = { 5e 92 [2] 7a 9c [2] 51 b0 [2] 7f 92 [2] 6b 89 [2] 64 93 [2] 7a 8e [2] 78 8f [2] 63 89 [2] 7f 8e [2] 63 a1 }

  condition:
    any of them
}