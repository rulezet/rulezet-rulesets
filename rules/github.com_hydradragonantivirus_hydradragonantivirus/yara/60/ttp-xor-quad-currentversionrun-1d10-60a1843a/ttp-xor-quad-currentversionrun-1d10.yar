rule TTP_XOR_QUAD_CurrentVersionRun_1d10 {
  strings:
    $key_1d10 = { 4e 7f [2] 6a 71 [2] 41 5d [2] 6f 7f [2] 7b 64 [2] 74 7e [2] 6a 63 [2] 68 62 [2] 73 64 [2] 6f 63 [2] 73 4c }

  condition:
    any of them
}