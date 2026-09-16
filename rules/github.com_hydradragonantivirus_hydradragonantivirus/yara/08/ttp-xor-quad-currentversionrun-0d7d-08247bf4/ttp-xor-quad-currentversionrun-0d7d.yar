rule TTP_XOR_QUAD_CurrentVersionRun_0d7d {
  strings:
    $key_0d7d = { 5e 12 [2] 7a 1c [2] 51 30 [2] 7f 12 [2] 6b 09 [2] 64 13 [2] 7a 0e [2] 78 0f [2] 63 09 [2] 7f 0e [2] 63 21 }

  condition:
    any of them
}