rule TTP_XOR_QUAD_CurrentVersionRun_ee6d {
  strings:
    $key_ee6d = { bd 02 [2] 99 0c [2] b2 20 [2] 9c 02 [2] 88 19 [2] 87 03 [2] 99 1e [2] 9b 1f [2] 80 19 [2] 9c 1e [2] 80 31 }

  condition:
    any of them
}