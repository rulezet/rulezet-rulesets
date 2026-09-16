rule TTP_XOR_QUAD_CurrentVersionRun_ee7c {
  strings:
    $key_ee7c = { bd 13 [2] 99 1d [2] b2 31 [2] 9c 13 [2] 88 08 [2] 87 12 [2] 99 0f [2] 9b 0e [2] 80 08 [2] 9c 0f [2] 80 20 }

  condition:
    any of them
}