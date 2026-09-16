rule TTP_XOR_QUAD_CurrentVersionRun_eee7 {
  strings:
    $key_eee7 = { bd 88 [2] 99 86 [2] b2 aa [2] 9c 88 [2] 88 93 [2] 87 89 [2] 99 94 [2] 9b 95 [2] 80 93 [2] 9c 94 [2] 80 bb }

  condition:
    any of them
}