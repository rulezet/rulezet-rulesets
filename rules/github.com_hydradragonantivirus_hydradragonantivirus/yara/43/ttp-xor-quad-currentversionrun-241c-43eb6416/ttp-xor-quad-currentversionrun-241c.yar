rule TTP_XOR_QUAD_CurrentVersionRun_241c {
  strings:
    $key_241c = { 77 73 [2] 53 7d [2] 78 51 [2] 56 73 [2] 42 68 [2] 4d 72 [2] 53 6f [2] 51 6e [2] 4a 68 [2] 56 6f [2] 4a 40 }

  condition:
    any of them
}