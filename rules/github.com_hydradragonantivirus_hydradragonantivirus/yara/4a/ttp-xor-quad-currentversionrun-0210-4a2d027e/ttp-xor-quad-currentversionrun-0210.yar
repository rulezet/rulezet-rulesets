rule TTP_XOR_QUAD_CurrentVersionRun_0210 {
  strings:
    $key_0210 = { 51 7f [2] 75 71 [2] 5e 5d [2] 70 7f [2] 64 64 [2] 6b 7e [2] 75 63 [2] 77 62 [2] 6c 64 [2] 70 63 [2] 6c 4c }

  condition:
    any of them
}