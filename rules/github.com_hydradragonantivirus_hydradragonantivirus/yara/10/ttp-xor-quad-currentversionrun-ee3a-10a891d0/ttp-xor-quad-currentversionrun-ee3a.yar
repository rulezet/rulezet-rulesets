rule TTP_XOR_QUAD_CurrentVersionRun_ee3a {
  strings:
    $key_ee3a = { bd 55 [2] 99 5b [2] b2 77 [2] 9c 55 [2] 88 4e [2] 87 54 [2] 99 49 [2] 9b 48 [2] 80 4e [2] 9c 49 [2] 80 66 }

  condition:
    any of them
}