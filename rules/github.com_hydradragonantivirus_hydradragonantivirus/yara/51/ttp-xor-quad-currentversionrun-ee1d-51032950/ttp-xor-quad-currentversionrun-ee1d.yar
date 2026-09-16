rule TTP_XOR_QUAD_CurrentVersionRun_ee1d {
  strings:
    $key_ee1d = { bd 72 [2] 99 7c [2] b2 50 [2] 9c 72 [2] 88 69 [2] 87 73 [2] 99 6e [2] 9b 6f [2] 80 69 [2] 9c 6e [2] 80 41 }

  condition:
    any of them
}