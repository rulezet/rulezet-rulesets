rule TTP_XOR_QUAD_CurrentVersionRun_e930 {
  strings:
    $key_e930 = { ba 5f [2] 9e 51 [2] b5 7d [2] 9b 5f [2] 8f 44 [2] 80 5e [2] 9e 43 [2] 9c 42 [2] 87 44 [2] 9b 43 [2] 87 6c }

  condition:
    any of them
}