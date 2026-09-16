rule TTP_XOR_QUAD_CurrentVersionRun_0110 {
  strings:
    $key_0110 = { 52 7f [2] 76 71 [2] 5d 5d [2] 73 7f [2] 67 64 [2] 68 7e [2] 76 63 [2] 74 62 [2] 6f 64 [2] 73 63 [2] 6f 4c }

  condition:
    any of them
}