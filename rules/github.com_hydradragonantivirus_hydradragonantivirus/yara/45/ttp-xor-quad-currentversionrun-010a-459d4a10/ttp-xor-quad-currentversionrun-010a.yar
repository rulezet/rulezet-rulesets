rule TTP_XOR_QUAD_CurrentVersionRun_010a {
  strings:
    $key_010a = { 52 65 [2] 76 6b [2] 5d 47 [2] 73 65 [2] 67 7e [2] 68 64 [2] 76 79 [2] 74 78 [2] 6f 7e [2] 73 79 [2] 6f 56 }

  condition:
    any of them
}