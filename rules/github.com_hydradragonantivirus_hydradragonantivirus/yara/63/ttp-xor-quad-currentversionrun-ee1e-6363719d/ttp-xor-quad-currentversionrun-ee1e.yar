rule TTP_XOR_QUAD_CurrentVersionRun_ee1e {
  strings:
    $key_ee1e = { bd 71 [2] 99 7f [2] b2 53 [2] 9c 71 [2] 88 6a [2] 87 70 [2] 99 6d [2] 9b 6c [2] 80 6a [2] 9c 6d [2] 80 42 }

  condition:
    any of them
}