rule TTP_XOR_QUAD_CurrentVersionRun_ee7d {
  strings:
    $key_ee7d = { bd 12 [2] 99 1c [2] b2 30 [2] 9c 12 [2] 88 09 [2] 87 13 [2] 99 0e [2] 9b 0f [2] 80 09 [2] 9c 0e [2] 80 21 }

  condition:
    any of them
}