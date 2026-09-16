rule TTP_XOR_QUAD_CurrentVersionRun_1610 {
  strings:
    $key_1610 = { 45 7f [2] 61 71 [2] 4a 5d [2] 64 7f [2] 70 64 [2] 7f 7e [2] 61 63 [2] 63 62 [2] 78 64 [2] 64 63 [2] 78 4c }

  condition:
    any of them
}