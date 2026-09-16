rule TTP_XOR_QUAD_CurrentVersionRun_011c {
  strings:
    $key_011c = { 52 73 [2] 76 7d [2] 5d 51 [2] 73 73 [2] 67 68 [2] 68 72 [2] 76 6f [2] 74 6e [2] 6f 68 [2] 73 6f [2] 6f 40 }

  condition:
    any of them
}