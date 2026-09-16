rule TTP_XOR_QUAD_CurrentVersionRun_ee7a {
  strings:
    $key_ee7a = { bd 15 [2] 99 1b [2] b2 37 [2] 9c 15 [2] 88 0e [2] 87 14 [2] 99 09 [2] 9b 08 [2] 80 0e [2] 9c 09 [2] 80 26 }

  condition:
    any of them
}