rule TTP_XOR_QUAD_CurrentVersionRun_ee1a {
  strings:
    $key_ee1a = { bd 75 [2] 99 7b [2] b2 57 [2] 9c 75 [2] 88 6e [2] 87 74 [2] 99 69 [2] 9b 68 [2] 80 6e [2] 9c 69 [2] 80 46 }

  condition:
    any of them
}