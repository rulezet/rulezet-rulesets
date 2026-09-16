rule TTP_XOR_QUAD_CurrentVersionRun_125d {
  strings:
    $key_125d = { 41 32 [2] 65 3c [2] 4e 10 [2] 60 32 [2] 74 29 [2] 7b 33 [2] 65 2e [2] 67 2f [2] 7c 29 [2] 60 2e [2] 7c 01 }

  condition:
    any of them
}