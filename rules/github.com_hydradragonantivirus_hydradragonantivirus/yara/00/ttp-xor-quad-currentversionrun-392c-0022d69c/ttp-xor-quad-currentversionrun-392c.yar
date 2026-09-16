rule TTP_XOR_QUAD_CurrentVersionRun_392c {
  strings:
    $key_392c = { 6a 43 [2] 4e 4d [2] 65 61 [2] 4b 43 [2] 5f 58 [2] 50 42 [2] 4e 5f [2] 4c 5e [2] 57 58 [2] 4b 5f [2] 57 70 }

  condition:
    any of them
}