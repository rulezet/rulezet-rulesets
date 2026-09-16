rule TTP_XOR_QUAD_CurrentVersionRun_6d1c {
  strings:
    $key_6d1c = { 3e 73 [2] 1a 7d [2] 31 51 [2] 1f 73 [2] 0b 68 [2] 04 72 [2] 1a 6f [2] 18 6e [2] 03 68 [2] 1f 6f [2] 03 40 }

  condition:
    any of them
}