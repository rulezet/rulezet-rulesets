rule TTP_XOR_QUAD_CurrentVersionRun_ee08 {
  strings:
    $key_ee08 = { bd 67 [2] 99 69 [2] b2 45 [2] 9c 67 [2] 88 7c [2] 87 66 [2] 99 7b [2] 9b 7a [2] 80 7c [2] 9c 7b [2] 80 54 }

  condition:
    any of them
}