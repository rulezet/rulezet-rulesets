rule TTP_XOR_QUAD_CurrentVersionRun_1310 {
  strings:
    $key_1310 = { 40 7f [2] 64 71 [2] 4f 5d [2] 61 7f [2] 75 64 [2] 7a 7e [2] 64 63 [2] 66 62 [2] 7d 64 [2] 61 63 [2] 7d 4c }

  condition:
    any of them
}