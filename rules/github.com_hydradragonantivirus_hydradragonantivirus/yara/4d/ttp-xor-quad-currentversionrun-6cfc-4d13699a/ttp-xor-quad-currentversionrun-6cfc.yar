rule TTP_XOR_QUAD_CurrentVersionRun_6cfc {
  strings:
    $key_6cfc = { 3f 93 [2] 1b 9d [2] 30 b1 [2] 1e 93 [2] 0a 88 [2] 05 92 [2] 1b 8f [2] 19 8e [2] 02 88 [2] 1e 8f [2] 02 a0 }

  condition:
    any of them
}