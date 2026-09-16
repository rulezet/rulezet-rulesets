rule TTP_XOR_QUAD_CurrentVersionRun_0d00 {
  strings:
    $key_0d00 = { 5e 6f [2] 7a 61 [2] 51 4d [2] 7f 6f [2] 6b 74 [2] 64 6e [2] 7a 73 [2] 78 72 [2] 63 74 [2] 7f 73 [2] 63 5c }

  condition:
    any of them
}