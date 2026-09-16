rule TTP_XOR_QUAD_CurrentVersionRun_095d {
  strings:
    $key_095d = { 5a 32 [2] 7e 3c [2] 55 10 [2] 7b 32 [2] 6f 29 [2] 60 33 [2] 7e 2e [2] 7c 2f [2] 67 29 [2] 7b 2e [2] 67 01 }

  condition:
    any of them
}