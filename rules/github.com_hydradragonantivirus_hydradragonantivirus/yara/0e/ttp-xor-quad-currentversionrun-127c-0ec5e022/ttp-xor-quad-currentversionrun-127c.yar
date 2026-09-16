rule TTP_XOR_QUAD_CurrentVersionRun_127c {
  strings:
    $key_127c = { 41 13 [2] 65 1d [2] 4e 31 [2] 60 13 [2] 74 08 [2] 7b 12 [2] 65 0f [2] 67 0e [2] 7c 08 [2] 60 0f [2] 7c 20 }

  condition:
    any of them
}