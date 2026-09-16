rule TTP_XOR_QUAD_CurrentVersionRun_ee71 {
  strings:
    $key_ee71 = { bd 1e [2] 99 10 [2] b2 3c [2] 9c 1e [2] 88 05 [2] 87 1f [2] 99 02 [2] 9b 03 [2] 80 05 [2] 9c 02 [2] 80 2d }

  condition:
    any of them
}