rule TTP_XOR_QUAD_CurrentVersionRun_6c10 {
  strings:
    $key_6c10 = { 3f 7f [2] 1b 71 [2] 30 5d [2] 1e 7f [2] 0a 64 [2] 05 7e [2] 1b 63 [2] 19 62 [2] 02 64 [2] 1e 63 [2] 02 4c }

  condition:
    any of them
}