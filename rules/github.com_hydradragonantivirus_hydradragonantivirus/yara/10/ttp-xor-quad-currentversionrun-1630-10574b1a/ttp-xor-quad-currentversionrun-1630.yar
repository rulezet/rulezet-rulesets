rule TTP_XOR_QUAD_CurrentVersionRun_1630 {
  strings:
    $key_1630 = { 45 5f [2] 61 51 [2] 4a 7d [2] 64 5f [2] 70 44 [2] 7f 5e [2] 61 43 [2] 63 42 [2] 78 44 [2] 64 43 [2] 78 6c }

  condition:
    any of them
}