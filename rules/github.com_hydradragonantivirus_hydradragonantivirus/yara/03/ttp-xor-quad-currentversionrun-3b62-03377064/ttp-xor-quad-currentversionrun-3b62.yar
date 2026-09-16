rule TTP_XOR_QUAD_CurrentVersionRun_3b62 {
  strings:
    $key_3b62 = { 68 0d [2] 4c 03 [2] 67 2f [2] 49 0d [2] 5d 16 [2] 52 0c [2] 4c 11 [2] 4e 10 [2] 55 16 [2] 49 11 [2] 55 3e }

  condition:
    any of them
}