rule TTP_XOR_QUAD_CurrentVersionRun_9104 {
  strings:
    $key_9104 = { c2 6b [2] e6 65 [2] cd 49 [2] e3 6b [2] f7 70 [2] f8 6a [2] e6 77 [2] e4 76 [2] ff 70 [2] e3 77 [2] ff 58 }

  condition:
    any of them
}