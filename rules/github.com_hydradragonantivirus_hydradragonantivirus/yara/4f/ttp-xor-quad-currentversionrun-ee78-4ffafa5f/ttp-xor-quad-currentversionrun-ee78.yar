rule TTP_XOR_QUAD_CurrentVersionRun_ee78 {
  strings:
    $key_ee78 = { bd 17 [2] 99 19 [2] b2 35 [2] 9c 17 [2] 88 0c [2] 87 16 [2] 99 0b [2] 9b 0a [2] 80 0c [2] 9c 0b [2] 80 24 }

  condition:
    any of them
}