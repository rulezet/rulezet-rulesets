rule TTP_XOR_QUAD_CurrentVersionRun_ee7e {
  strings:
    $key_ee7e = { bd 11 [2] 99 1f [2] b2 33 [2] 9c 11 [2] 88 0a [2] 87 10 [2] 99 0d [2] 9b 0c [2] 80 0a [2] 9c 0d [2] 80 22 }

  condition:
    any of them
}