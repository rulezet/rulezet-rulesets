rule TTP_XOR_QUAD_CurrentVersionRun_12e1 {
  strings:
    $key_12e1 = { 41 8e [2] 65 80 [2] 4e ac [2] 60 8e [2] 74 95 [2] 7b 8f [2] 65 92 [2] 67 93 [2] 7c 95 [2] 60 92 [2] 7c bd }

  condition:
    any of them
}