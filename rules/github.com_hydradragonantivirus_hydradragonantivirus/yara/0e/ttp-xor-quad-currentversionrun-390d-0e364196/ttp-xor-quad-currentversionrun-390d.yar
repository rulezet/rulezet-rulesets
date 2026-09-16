rule TTP_XOR_QUAD_CurrentVersionRun_390d {
  strings:
    $key_390d = { 6a 62 [2] 4e 6c [2] 65 40 [2] 4b 62 [2] 5f 79 [2] 50 63 [2] 4e 7e [2] 4c 7f [2] 57 79 [2] 4b 7e [2] 57 51 }

  condition:
    any of them
}