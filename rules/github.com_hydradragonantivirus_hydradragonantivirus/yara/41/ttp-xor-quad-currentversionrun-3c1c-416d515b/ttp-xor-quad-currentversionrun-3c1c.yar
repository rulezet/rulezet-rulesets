rule TTP_XOR_QUAD_CurrentVersionRun_3c1c {
  strings:
    $key_3c1c = { 6f 73 [2] 4b 7d [2] 60 51 [2] 4e 73 [2] 5a 68 [2] 55 72 [2] 4b 6f [2] 49 6e [2] 52 68 [2] 4e 6f [2] 52 40 }

  condition:
    any of them
}