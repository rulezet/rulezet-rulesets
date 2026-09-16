rule TTP_XOR_QUAD_CurrentVersionRun_491c {
  strings:
    $key_491c = { 1a 73 [2] 3e 7d [2] 15 51 [2] 3b 73 [2] 2f 68 [2] 20 72 [2] 3e 6f [2] 3c 6e [2] 27 68 [2] 3b 6f [2] 27 40 }

  condition:
    any of them
}