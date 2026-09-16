rule TTP_XOR_QUAD_CurrentVersionRun_72e1 {
  strings:
    $key_72e1 = { 21 8e [2] 05 80 [2] 2e ac [2] 00 8e [2] 14 95 [2] 1b 8f [2] 05 92 [2] 07 93 [2] 1c 95 [2] 00 92 [2] 1c bd }

  condition:
    any of them
}