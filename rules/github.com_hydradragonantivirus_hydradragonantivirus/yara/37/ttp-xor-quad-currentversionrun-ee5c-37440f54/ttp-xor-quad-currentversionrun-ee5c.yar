rule TTP_XOR_QUAD_CurrentVersionRun_ee5c {
  strings:
    $key_ee5c = { bd 33 [2] 99 3d [2] b2 11 [2] 9c 33 [2] 88 28 [2] 87 32 [2] 99 2f [2] 9b 2e [2] 80 28 [2] 9c 2f [2] 80 00 }

  condition:
    any of them
}