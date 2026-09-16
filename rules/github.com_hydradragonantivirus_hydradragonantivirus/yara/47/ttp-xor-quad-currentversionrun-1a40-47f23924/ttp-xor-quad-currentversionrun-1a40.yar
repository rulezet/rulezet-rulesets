rule TTP_XOR_QUAD_CurrentVersionRun_1a40 {
  strings:
    $key_1a40 = { 49 2f [2] 6d 21 [2] 46 0d [2] 68 2f [2] 7c 34 [2] 73 2e [2] 6d 33 [2] 6f 32 [2] 74 34 [2] 68 33 [2] 74 1c }

  condition:
    any of them
}