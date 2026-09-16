rule TTP_XOR_QUAD_CurrentVersionRun_5610 {
  strings:
    $key_5610 = { 05 7f [2] 21 71 [2] 0a 5d [2] 24 7f [2] 30 64 [2] 3f 7e [2] 21 63 [2] 23 62 [2] 38 64 [2] 24 63 [2] 38 4c }

  condition:
    any of them
}