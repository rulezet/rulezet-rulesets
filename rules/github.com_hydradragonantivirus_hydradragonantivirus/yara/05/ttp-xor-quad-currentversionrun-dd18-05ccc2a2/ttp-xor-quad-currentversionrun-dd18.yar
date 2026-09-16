rule TTP_XOR_QUAD_CurrentVersionRun_dd18 {
  strings:
    $key_dd18 = { 8e 77 [2] aa 79 [2] 81 55 [2] af 77 [2] bb 6c [2] b4 76 [2] aa 6b [2] a8 6a [2] b3 6c [2] af 6b [2] b3 44 }

  condition:
    any of them
}