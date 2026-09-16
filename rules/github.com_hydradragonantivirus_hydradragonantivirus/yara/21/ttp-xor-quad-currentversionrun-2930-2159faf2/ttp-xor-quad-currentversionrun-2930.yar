rule TTP_XOR_QUAD_CurrentVersionRun_2930 {
  strings:
    $key_2930 = { 7a 5f [2] 5e 51 [2] 75 7d [2] 5b 5f [2] 4f 44 [2] 40 5e [2] 5e 43 [2] 5c 42 [2] 47 44 [2] 5b 43 [2] 47 6c }

  condition:
    any of them
}