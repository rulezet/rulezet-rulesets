rule TTP_XOR_QUAD_CurrentVersionRun_017a {
  strings:
    $key_017a = { 52 15 [2] 76 1b [2] 5d 37 [2] 73 15 [2] 67 0e [2] 68 14 [2] 76 09 [2] 74 08 [2] 6f 0e [2] 73 09 [2] 6f 26 }

  condition:
    any of them
}