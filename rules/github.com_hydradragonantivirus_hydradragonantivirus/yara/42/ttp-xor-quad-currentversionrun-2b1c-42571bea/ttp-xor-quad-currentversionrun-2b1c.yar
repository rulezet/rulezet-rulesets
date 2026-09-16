rule TTP_XOR_QUAD_CurrentVersionRun_2b1c {
  strings:
    $key_2b1c = { 78 73 [2] 5c 7d [2] 77 51 [2] 59 73 [2] 4d 68 [2] 42 72 [2] 5c 6f [2] 5e 6e [2] 45 68 [2] 59 6f [2] 45 40 }

  condition:
    any of them
}