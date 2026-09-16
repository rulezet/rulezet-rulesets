rule TTP_XOR_QUAD_CurrentVersionRun_3bed {
  strings:
    $key_3bed = { 68 82 [2] 4c 8c [2] 67 a0 [2] 49 82 [2] 5d 99 [2] 52 83 [2] 4c 9e [2] 4e 9f [2] 55 99 [2] 49 9e [2] 55 b1 }

  condition:
    any of them
}