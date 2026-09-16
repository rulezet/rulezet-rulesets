rule TTP_XOR_QUAD_CurrentVersionRun_381d {
  strings:
    $key_381d = { 6b 72 [2] 4f 7c [2] 64 50 [2] 4a 72 [2] 5e 69 [2] 51 73 [2] 4f 6e [2] 4d 6f [2] 56 69 [2] 4a 6e [2] 56 41 }

  condition:
    any of them
}