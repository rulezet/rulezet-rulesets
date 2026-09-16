rule TTP_XOR_QUAD_CurrentVersionRun_1b10 {
  strings:
    $key_1b10 = { 48 7f [2] 6c 71 [2] 47 5d [2] 69 7f [2] 7d 64 [2] 72 7e [2] 6c 63 [2] 6e 62 [2] 75 64 [2] 69 63 [2] 75 4c }

  condition:
    any of them
}