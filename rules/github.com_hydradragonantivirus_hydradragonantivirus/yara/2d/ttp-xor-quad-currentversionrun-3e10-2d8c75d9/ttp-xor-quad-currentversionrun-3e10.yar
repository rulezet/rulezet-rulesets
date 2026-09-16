rule TTP_XOR_QUAD_CurrentVersionRun_3e10 {
  strings:
    $key_3e10 = { 6d 7f [2] 49 71 [2] 62 5d [2] 4c 7f [2] 58 64 [2] 57 7e [2] 49 63 [2] 4b 62 [2] 50 64 [2] 4c 63 [2] 50 4c }

  condition:
    any of them
}