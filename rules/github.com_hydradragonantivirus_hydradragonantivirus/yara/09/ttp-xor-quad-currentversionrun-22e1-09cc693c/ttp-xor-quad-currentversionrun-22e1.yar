rule TTP_XOR_QUAD_CurrentVersionRun_22e1 {
  strings:
    $key_22e1 = { 71 8e [2] 55 80 [2] 7e ac [2] 50 8e [2] 44 95 [2] 4b 8f [2] 55 92 [2] 57 93 [2] 4c 95 [2] 50 92 [2] 4c bd }

  condition:
    any of them
}