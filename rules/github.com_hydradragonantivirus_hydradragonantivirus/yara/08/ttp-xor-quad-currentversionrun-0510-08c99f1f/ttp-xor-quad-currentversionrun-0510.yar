rule TTP_XOR_QUAD_CurrentVersionRun_0510 {
  strings:
    $key_0510 = { 56 7f [2] 72 71 [2] 59 5d [2] 77 7f [2] 63 64 [2] 6c 7e [2] 72 63 [2] 70 62 [2] 6b 64 [2] 77 63 [2] 6b 4c }

  condition:
    any of them
}