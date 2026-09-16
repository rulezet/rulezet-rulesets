rule TTP_XOR_QUAD_CurrentVersionRun_ee0e {
  strings:
    $key_ee0e = { bd 61 [2] 99 6f [2] b2 43 [2] 9c 61 [2] 88 7a [2] 87 60 [2] 99 7d [2] 9b 7c [2] 80 7a [2] 9c 7d [2] 80 52 }

  condition:
    any of them
}