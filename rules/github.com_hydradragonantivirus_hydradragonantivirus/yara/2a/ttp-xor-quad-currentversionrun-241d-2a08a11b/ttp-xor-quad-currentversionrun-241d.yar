rule TTP_XOR_QUAD_CurrentVersionRun_241d {
  strings:
    $key_241d = { 77 72 [2] 53 7c [2] 78 50 [2] 56 72 [2] 42 69 [2] 4d 73 [2] 53 6e [2] 51 6f [2] 4a 69 [2] 56 6e [2] 4a 41 }

  condition:
    any of them
}