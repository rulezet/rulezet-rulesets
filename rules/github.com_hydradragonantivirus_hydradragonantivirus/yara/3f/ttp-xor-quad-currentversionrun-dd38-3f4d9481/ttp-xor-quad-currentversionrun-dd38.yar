rule TTP_XOR_QUAD_CurrentVersionRun_dd38 {
  strings:
    $key_dd38 = { 8e 57 [2] aa 59 [2] 81 75 [2] af 57 [2] bb 4c [2] b4 56 [2] aa 4b [2] a8 4a [2] b3 4c [2] af 4b [2] b3 64 }

  condition:
    any of them
}