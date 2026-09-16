rule TTP_XOR_QUAD_CurrentVersionRun_2f6d {
  strings:
    $key_2f6d = { 7c 02 [2] 58 0c [2] 73 20 [2] 5d 02 [2] 49 19 [2] 46 03 [2] 58 1e [2] 5a 1f [2] 41 19 [2] 5d 1e [2] 41 31 }

  condition:
    any of them
}