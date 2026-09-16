rule TTP_XOR_QUAD_CurrentVersionRun_ee32 {
  strings:
    $key_ee32 = { bd 5d [2] 99 53 [2] b2 7f [2] 9c 5d [2] 88 46 [2] 87 5c [2] 99 41 [2] 9b 40 [2] 80 46 [2] 9c 41 [2] 80 6e }

  condition:
    any of them
}