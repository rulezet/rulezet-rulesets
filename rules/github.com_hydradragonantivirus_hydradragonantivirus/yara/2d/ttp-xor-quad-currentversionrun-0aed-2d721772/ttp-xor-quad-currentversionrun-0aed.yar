rule TTP_XOR_QUAD_CurrentVersionRun_0aed {
  strings:
    $key_0aed = { 59 82 [2] 7d 8c [2] 56 a0 [2] 78 82 [2] 6c 99 [2] 63 83 [2] 7d 9e [2] 7f 9f [2] 64 99 [2] 78 9e [2] 64 b1 }

  condition:
    any of them
}