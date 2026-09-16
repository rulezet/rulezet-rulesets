rule TTP_XOR_QUAD_CurrentVersionRun_0b0c {
  strings:
    $key_0b0c = { 58 63 [2] 7c 6d [2] 57 41 [2] 79 63 [2] 6d 78 [2] 62 62 [2] 7c 7f [2] 7e 7e [2] 65 78 [2] 79 7f [2] 65 50 }

  condition:
    any of them
}