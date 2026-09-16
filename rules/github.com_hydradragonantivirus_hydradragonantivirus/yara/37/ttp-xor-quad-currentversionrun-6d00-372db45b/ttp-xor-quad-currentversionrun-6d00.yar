rule TTP_XOR_QUAD_CurrentVersionRun_6d00 {
  strings:
    $key_6d00 = { 3e 6f [2] 1a 61 [2] 31 4d [2] 1f 6f [2] 0b 74 [2] 04 6e [2] 1a 73 [2] 18 72 [2] 03 74 [2] 1f 73 [2] 03 5c }

  condition:
    any of them
}