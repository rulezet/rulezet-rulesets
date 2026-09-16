rule TTP_XOR_QUAD_CurrentVersionRun_eefa {
  strings:
    $key_eefa = { bd 95 [2] 99 9b [2] b2 b7 [2] 9c 95 [2] 88 8e [2] 87 94 [2] 99 89 [2] 9b 88 [2] 80 8e [2] 9c 89 [2] 80 a6 }

  condition:
    any of them
}