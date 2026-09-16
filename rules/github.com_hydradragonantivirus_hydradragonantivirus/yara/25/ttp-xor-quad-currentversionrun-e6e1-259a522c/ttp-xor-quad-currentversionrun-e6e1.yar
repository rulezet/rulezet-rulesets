rule TTP_XOR_QUAD_CurrentVersionRun_e6e1 {
  strings:
    $key_e6e1 = { b5 8e [2] 91 80 [2] ba ac [2] 94 8e [2] 80 95 [2] 8f 8f [2] 91 92 [2] 93 93 [2] 88 95 [2] 94 92 [2] 88 bd }

  condition:
    any of them
}