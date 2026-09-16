rule TTP_XOR_QUAD_CurrentVersionRun_016d {
  strings:
    $key_016d = { 52 02 [2] 76 0c [2] 5d 20 [2] 73 02 [2] 67 19 [2] 68 03 [2] 76 1e [2] 74 1f [2] 6f 19 [2] 73 1e [2] 6f 31 }

  condition:
    any of them
}