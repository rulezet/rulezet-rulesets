rule TTP_XOR_QUAD_CurrentVersionRun_091d {
  strings:
    $key_091d = { 5a 72 [2] 7e 7c [2] 55 50 [2] 7b 72 [2] 6f 69 [2] 60 73 [2] 7e 6e [2] 7c 6f [2] 67 69 [2] 7b 6e [2] 67 41 }

  condition:
    any of them
}