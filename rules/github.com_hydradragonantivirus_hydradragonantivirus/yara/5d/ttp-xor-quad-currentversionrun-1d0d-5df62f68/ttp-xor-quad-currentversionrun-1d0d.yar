rule TTP_XOR_QUAD_CurrentVersionRun_1d0d {
  strings:
    $key_1d0d = { 4e 62 [2] 6a 6c [2] 41 40 [2] 6f 62 [2] 7b 79 [2] 74 63 [2] 6a 7e [2] 68 7f [2] 73 79 [2] 6f 7e [2] 73 51 }

  condition:
    any of them
}