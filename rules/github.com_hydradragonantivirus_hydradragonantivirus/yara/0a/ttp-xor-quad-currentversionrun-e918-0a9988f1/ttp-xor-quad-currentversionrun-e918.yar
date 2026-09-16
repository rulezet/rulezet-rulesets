rule TTP_XOR_QUAD_CurrentVersionRun_e918 {
  strings:
    $key_e918 = { ba 77 [2] 9e 79 [2] b5 55 [2] 9b 77 [2] 8f 6c [2] 80 76 [2] 9e 6b [2] 9c 6a [2] 87 6c [2] 9b 6b [2] 87 44 }

  condition:
    any of them
}