rule TTP_XOR_QUAD_CurrentVersionRun_2940 {
  strings:
    $key_2940 = { 7a 2f [2] 5e 21 [2] 75 0d [2] 5b 2f [2] 4f 34 [2] 40 2e [2] 5e 33 [2] 5c 32 [2] 47 34 [2] 5b 33 [2] 47 1c }

  condition:
    any of them
}