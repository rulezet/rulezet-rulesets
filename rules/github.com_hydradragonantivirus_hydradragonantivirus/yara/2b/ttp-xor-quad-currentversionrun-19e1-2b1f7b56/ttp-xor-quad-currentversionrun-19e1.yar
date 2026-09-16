rule TTP_XOR_QUAD_CurrentVersionRun_19e1 {
  strings:
    $key_19e1 = { 4a 8e [2] 6e 80 [2] 45 ac [2] 6b 8e [2] 7f 95 [2] 70 8f [2] 6e 92 [2] 6c 93 [2] 77 95 [2] 6b 92 [2] 77 bd }

  condition:
    any of them
}