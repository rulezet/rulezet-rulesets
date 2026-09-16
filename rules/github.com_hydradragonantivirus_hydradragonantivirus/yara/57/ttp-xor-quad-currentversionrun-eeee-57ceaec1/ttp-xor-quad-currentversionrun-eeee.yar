rule TTP_XOR_QUAD_CurrentVersionRun_eeee {
  strings:
    $key_eeee = { bd 81 [2] 99 8f [2] b2 a3 [2] 9c 81 [2] 88 9a [2] 87 80 [2] 99 9d [2] 9b 9c [2] 80 9a [2] 9c 9d [2] 80 b2 }

  condition:
    any of them
}