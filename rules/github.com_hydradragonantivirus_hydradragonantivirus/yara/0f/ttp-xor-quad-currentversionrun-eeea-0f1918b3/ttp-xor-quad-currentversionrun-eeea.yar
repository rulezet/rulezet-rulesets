rule TTP_XOR_QUAD_CurrentVersionRun_eeea {
  strings:
    $key_eeea = { bd 85 [2] 99 8b [2] b2 a7 [2] 9c 85 [2] 88 9e [2] 87 84 [2] 99 99 [2] 9b 98 [2] 80 9e [2] 9c 99 [2] 80 b6 }

  condition:
    any of them
}