rule TTP_XOR_QUAD_CurrentVersionRun_ee39 {
  strings:
    $key_ee39 = { bd 56 [2] 99 58 [2] b2 74 [2] 9c 56 [2] 88 4d [2] 87 57 [2] 99 4a [2] 9b 4b [2] 80 4d [2] 9c 4a [2] 80 65 }

  condition:
    any of them
}