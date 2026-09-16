rule TTP_XOR_QUAD_CurrentVersionRun_0dfc {
  strings:
    $key_0dfc = { 5e 93 [2] 7a 9d [2] 51 b1 [2] 7f 93 [2] 6b 88 [2] 64 92 [2] 7a 8f [2] 78 8e [2] 63 88 [2] 7f 8f [2] 63 a0 }

  condition:
    any of them
}