rule TTP_XOR_QUAD_CurrentVersionRun_eee1 {
  strings:
    $key_eee1 = { bd 8e [2] 99 80 [2] b2 ac [2] 9c 8e [2] 88 95 [2] 87 8f [2] 99 92 [2] 9b 93 [2] 80 95 [2] 9c 92 [2] 80 bd }

  condition:
    any of them
}