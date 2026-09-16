rule TTP_XOR_QUAD_CurrentVersionRun_eeef {
  strings:
    $key_eeef = { bd 80 [2] 99 8e [2] b2 a2 [2] 9c 80 [2] 88 9b [2] 87 81 [2] 99 9c [2] 9b 9d [2] 80 9b [2] 9c 9c [2] 80 b3 }

  condition:
    any of them
}