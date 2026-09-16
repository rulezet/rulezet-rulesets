rule TTP_XOR_QUAD_CurrentVersionRun_101c {
  strings:
    $key_101c = { 43 73 [2] 67 7d [2] 4c 51 [2] 62 73 [2] 76 68 [2] 79 72 [2] 67 6f [2] 65 6e [2] 7e 68 [2] 62 6f [2] 7e 40 }

  condition:
    any of them
}