rule TTP_XOR_QUAD_CurrentVersionRun_3b1c {
  strings:
    $key_3b1c = { 68 73 [2] 4c 7d [2] 67 51 [2] 49 73 [2] 5d 68 [2] 52 72 [2] 4c 6f [2] 4e 6e [2] 55 68 [2] 49 6f [2] 55 40 }

  condition:
    any of them
}