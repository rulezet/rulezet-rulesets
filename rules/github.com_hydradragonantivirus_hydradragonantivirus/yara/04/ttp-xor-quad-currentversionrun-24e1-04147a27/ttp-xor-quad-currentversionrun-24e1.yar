rule TTP_XOR_QUAD_CurrentVersionRun_24e1 {
  strings:
    $key_24e1 = { 77 8e [2] 53 80 [2] 78 ac [2] 56 8e [2] 42 95 [2] 4d 8f [2] 53 92 [2] 51 93 [2] 4a 95 [2] 56 92 [2] 4a bd }

  condition:
    any of them
}