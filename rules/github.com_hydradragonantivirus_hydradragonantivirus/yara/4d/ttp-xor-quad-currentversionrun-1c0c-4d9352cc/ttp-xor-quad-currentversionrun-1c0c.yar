rule TTP_XOR_QUAD_CurrentVersionRun_1c0c {
  strings:
    $key_1c0c = { 4f 63 [2] 6b 6d [2] 40 41 [2] 6e 63 [2] 7a 78 [2] 75 62 [2] 6b 7f [2] 69 7e [2] 72 78 [2] 6e 7f [2] 72 50 }

  condition:
    any of them
}