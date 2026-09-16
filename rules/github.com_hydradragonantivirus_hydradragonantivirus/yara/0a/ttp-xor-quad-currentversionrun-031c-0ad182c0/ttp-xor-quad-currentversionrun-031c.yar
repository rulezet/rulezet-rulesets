rule TTP_XOR_QUAD_CurrentVersionRun_031c {
  strings:
    $key_031c = { 50 73 [2] 74 7d [2] 5f 51 [2] 71 73 [2] 65 68 [2] 6a 72 [2] 74 6f [2] 76 6e [2] 6d 68 [2] 71 6f [2] 6d 40 }

  condition:
    any of them
}