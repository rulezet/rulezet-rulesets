rule TTP_XOR_QUAD_CurrentVersionRun_ee4a {
  strings:
    $key_ee4a = { bd 25 [2] 99 2b [2] b2 07 [2] 9c 25 [2] 88 3e [2] 87 24 [2] 99 39 [2] 9b 38 [2] 80 3e [2] 9c 39 [2] 80 16 }

  condition:
    any of them
}