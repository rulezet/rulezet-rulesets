rule TTP_XOR_QUAD_CurrentVersionRun_3610 {
  strings:
    $key_3610 = { 65 7f [2] 41 71 [2] 6a 5d [2] 44 7f [2] 50 64 [2] 5f 7e [2] 41 63 [2] 43 62 [2] 58 64 [2] 44 63 [2] 58 4c }

  condition:
    any of them
}