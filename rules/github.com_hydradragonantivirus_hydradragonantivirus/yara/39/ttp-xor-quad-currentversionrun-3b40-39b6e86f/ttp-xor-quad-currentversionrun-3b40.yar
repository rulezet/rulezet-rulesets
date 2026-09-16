rule TTP_XOR_QUAD_CurrentVersionRun_3b40 {
  strings:
    $key_3b40 = { 68 2f [2] 4c 21 [2] 67 0d [2] 49 2f [2] 5d 34 [2] 52 2e [2] 4c 33 [2] 4e 32 [2] 55 34 [2] 49 33 [2] 55 1c }

  condition:
    any of them
}