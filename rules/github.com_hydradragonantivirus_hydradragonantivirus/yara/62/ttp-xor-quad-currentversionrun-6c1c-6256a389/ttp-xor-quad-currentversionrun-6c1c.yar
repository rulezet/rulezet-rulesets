rule TTP_XOR_QUAD_CurrentVersionRun_6c1c {
  strings:
    $key_6c1c = { 3f 73 [2] 1b 7d [2] 30 51 [2] 1e 73 [2] 0a 68 [2] 05 72 [2] 1b 6f [2] 19 6e [2] 02 68 [2] 1e 6f [2] 02 40 }

  condition:
    any of them
}