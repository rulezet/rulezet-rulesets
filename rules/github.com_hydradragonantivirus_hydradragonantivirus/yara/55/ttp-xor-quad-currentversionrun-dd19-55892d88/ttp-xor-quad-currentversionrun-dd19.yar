rule TTP_XOR_QUAD_CurrentVersionRun_dd19 {
  strings:
    $key_dd19 = { 8e 76 [2] aa 78 [2] 81 54 [2] af 76 [2] bb 6d [2] b4 77 [2] aa 6a [2] a8 6b [2] b3 6d [2] af 6a [2] b3 45 }

  condition:
    any of them
}