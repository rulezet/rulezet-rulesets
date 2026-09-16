rule TTP_XOR_QUAD_CurrentVersionRun_2950 {
  strings:
    $key_2950 = { 7a 3f [2] 5e 31 [2] 75 1d [2] 5b 3f [2] 4f 24 [2] 40 3e [2] 5e 23 [2] 5c 22 [2] 47 24 [2] 5b 23 [2] 47 0c }

  condition:
    any of them
}