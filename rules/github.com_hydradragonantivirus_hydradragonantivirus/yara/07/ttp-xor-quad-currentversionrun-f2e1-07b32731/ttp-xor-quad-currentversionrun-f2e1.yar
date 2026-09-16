rule TTP_XOR_QUAD_CurrentVersionRun_f2e1 {
  strings:
    $key_f2e1 = { a1 8e [2] 85 80 [2] ae ac [2] 80 8e [2] 94 95 [2] 9b 8f [2] 85 92 [2] 87 93 [2] 9c 95 [2] 80 92 [2] 9c bd }

  condition:
    any of them
}