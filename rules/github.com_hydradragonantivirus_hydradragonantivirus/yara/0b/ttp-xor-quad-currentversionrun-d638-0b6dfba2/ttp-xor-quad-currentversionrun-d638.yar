rule TTP_XOR_QUAD_CurrentVersionRun_d638 {
  strings:
    $key_d638 = { 85 57 [2] a1 59 [2] 8a 75 [2] a4 57 [2] b0 4c [2] bf 56 [2] a1 4b [2] a3 4a [2] b8 4c [2] a4 4b [2] b8 64 }

  condition:
    any of them
}