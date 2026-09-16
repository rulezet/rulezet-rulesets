rule TTP_XOR_QUAD_CurrentVersionRun_6b1c {
  strings:
    $key_6b1c = { 38 73 [2] 1c 7d [2] 37 51 [2] 19 73 [2] 0d 68 [2] 02 72 [2] 1c 6f [2] 1e 6e [2] 05 68 [2] 19 6f [2] 05 40 }

  condition:
    any of them
}