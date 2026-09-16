rule TTP_XOR_QUAD_CurrentVersionRun_3b7c {
  strings:
    $key_3b7c = { 68 13 [2] 4c 1d [2] 67 31 [2] 49 13 [2] 5d 08 [2] 52 12 [2] 4c 0f [2] 4e 0e [2] 55 08 [2] 49 0f [2] 55 20 }

  condition:
    any of them
}