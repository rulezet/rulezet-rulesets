rule TTP_XOR_QUAD_CurrentVersionRun_2be1 {
  strings:
    $key_2be1 = { 78 8e [2] 5c 80 [2] 77 ac [2] 59 8e [2] 4d 95 [2] 42 8f [2] 5c 92 [2] 5e 93 [2] 45 95 [2] 59 92 [2] 45 bd }

  condition:
    any of them
}