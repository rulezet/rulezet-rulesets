rule TTP_XOR_QUAD_CurrentVersionRun_017c {
  strings:
    $key_017c = { 52 13 [2] 76 1d [2] 5d 31 [2] 73 13 [2] 67 08 [2] 68 12 [2] 76 0f [2] 74 0e [2] 6f 08 [2] 73 0f [2] 6f 20 }

  condition:
    any of them
}