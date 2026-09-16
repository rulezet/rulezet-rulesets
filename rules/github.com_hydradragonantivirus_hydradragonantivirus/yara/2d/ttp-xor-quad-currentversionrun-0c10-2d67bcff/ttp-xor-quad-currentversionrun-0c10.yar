rule TTP_XOR_QUAD_CurrentVersionRun_0c10 {
  strings:
    $key_0c10 = { 5f 7f [2] 7b 71 [2] 50 5d [2] 7e 7f [2] 6a 64 [2] 65 7e [2] 7b 63 [2] 79 62 [2] 62 64 [2] 7e 63 [2] 62 4c }

  condition:
    any of them
}