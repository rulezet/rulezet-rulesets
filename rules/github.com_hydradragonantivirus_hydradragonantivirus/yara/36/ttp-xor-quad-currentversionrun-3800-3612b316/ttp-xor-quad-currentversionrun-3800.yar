rule TTP_XOR_QUAD_CurrentVersionRun_3800 {
  strings:
    $key_3800 = { 6b 6f [2] 4f 61 [2] 64 4d [2] 4a 6f [2] 5e 74 [2] 51 6e [2] 4f 73 [2] 4d 72 [2] 56 74 [2] 4a 73 [2] 56 5c }

  condition:
    any of them
}