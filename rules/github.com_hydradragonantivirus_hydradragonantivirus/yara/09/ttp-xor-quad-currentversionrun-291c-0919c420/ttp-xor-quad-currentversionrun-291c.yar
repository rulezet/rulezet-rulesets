rule TTP_XOR_QUAD_CurrentVersionRun_291c {
  strings:
    $key_291c = { 7a 73 [2] 5e 7d [2] 75 51 [2] 5b 73 [2] 4f 68 [2] 40 72 [2] 5e 6f [2] 5c 6e [2] 47 68 [2] 5b 6f [2] 47 40 }

  condition:
    any of them
}