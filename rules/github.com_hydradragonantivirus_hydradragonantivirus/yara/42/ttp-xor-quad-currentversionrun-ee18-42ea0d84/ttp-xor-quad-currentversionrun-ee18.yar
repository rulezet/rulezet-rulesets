rule TTP_XOR_QUAD_CurrentVersionRun_ee18 {
  strings:
    $key_ee18 = { bd 77 [2] 99 79 [2] b2 55 [2] 9c 77 [2] 88 6c [2] 87 76 [2] 99 6b [2] 9b 6a [2] 80 6c [2] 9c 6b [2] 80 44 }

  condition:
    any of them
}