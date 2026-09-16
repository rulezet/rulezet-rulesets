rule TTP_XOR_QUAD_CurrentVersionRun_ee3e {
  strings:
    $key_ee3e = { bd 51 [2] 99 5f [2] b2 73 [2] 9c 51 [2] 88 4a [2] 87 50 [2] 99 4d [2] 9b 4c [2] 80 4a [2] 9c 4d [2] 80 62 }

  condition:
    any of them
}