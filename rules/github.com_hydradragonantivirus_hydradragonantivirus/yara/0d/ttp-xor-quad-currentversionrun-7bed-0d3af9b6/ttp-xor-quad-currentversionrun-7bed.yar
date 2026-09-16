rule TTP_XOR_QUAD_CurrentVersionRun_7bed {
  strings:
    $key_7bed = { 28 82 [2] 0c 8c [2] 27 a0 [2] 09 82 [2] 1d 99 [2] 12 83 [2] 0c 9e [2] 0e 9f [2] 15 99 [2] 09 9e [2] 15 b1 }

  condition:
    any of them
}