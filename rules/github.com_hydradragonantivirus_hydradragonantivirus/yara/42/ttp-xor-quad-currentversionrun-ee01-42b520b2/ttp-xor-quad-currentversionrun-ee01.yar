rule TTP_XOR_QUAD_CurrentVersionRun_ee01 {
  strings:
    $key_ee01 = { bd 6e [2] 99 60 [2] b2 4c [2] 9c 6e [2] 88 75 [2] 87 6f [2] 99 72 [2] 9b 73 [2] 80 75 [2] 9c 72 [2] 80 5d }

  condition:
    any of them
}