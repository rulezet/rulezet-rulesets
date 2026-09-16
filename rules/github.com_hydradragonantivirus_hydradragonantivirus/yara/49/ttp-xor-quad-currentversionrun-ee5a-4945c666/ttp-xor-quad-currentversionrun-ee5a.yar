rule TTP_XOR_QUAD_CurrentVersionRun_ee5a {
  strings:
    $key_ee5a = { bd 35 [2] 99 3b [2] b2 17 [2] 9c 35 [2] 88 2e [2] 87 34 [2] 99 29 [2] 9b 28 [2] 80 2e [2] 9c 29 [2] 80 06 }

  condition:
    any of them
}