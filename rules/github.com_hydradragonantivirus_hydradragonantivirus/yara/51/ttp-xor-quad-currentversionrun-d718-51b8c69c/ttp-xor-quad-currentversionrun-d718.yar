rule TTP_XOR_QUAD_CurrentVersionRun_d718 {
  strings:
    $key_d718 = { 84 77 [2] a0 79 [2] 8b 55 [2] a5 77 [2] b1 6c [2] be 76 [2] a0 6b [2] a2 6a [2] b9 6c [2] a5 6b [2] b9 44 }

  condition:
    any of them
}