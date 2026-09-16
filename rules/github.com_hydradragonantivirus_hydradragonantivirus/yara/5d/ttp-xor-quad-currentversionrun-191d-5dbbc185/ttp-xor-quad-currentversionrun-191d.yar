rule TTP_XOR_QUAD_CurrentVersionRun_191d {
  strings:
    $key_191d = { 4a 72 [2] 6e 7c [2] 45 50 [2] 6b 72 [2] 7f 69 [2] 70 73 [2] 6e 6e [2] 6c 6f [2] 77 69 [2] 6b 6e [2] 77 41 }

  condition:
    any of them
}