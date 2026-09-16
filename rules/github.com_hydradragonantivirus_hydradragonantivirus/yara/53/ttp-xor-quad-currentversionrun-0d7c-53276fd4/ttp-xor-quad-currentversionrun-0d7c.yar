rule TTP_XOR_QUAD_CurrentVersionRun_0d7c {
  strings:
    $key_0d7c = { 5e 13 [2] 7a 1d [2] 51 31 [2] 7f 13 [2] 6b 08 [2] 64 12 [2] 7a 0f [2] 78 0e [2] 63 08 [2] 7f 0f [2] 63 20 }

  condition:
    any of them
}