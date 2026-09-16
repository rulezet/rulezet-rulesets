rule TTP_XOR_QUAD_CurrentVersionRun_ee6c {
  strings:
    $key_ee6c = { bd 03 [2] 99 0d [2] b2 21 [2] 9c 03 [2] 88 18 [2] 87 02 [2] 99 1f [2] 9b 1e [2] 80 18 [2] 9c 1f [2] 80 30 }

  condition:
    any of them
}