rule TTP_XOR_QUAD_CurrentVersionRun_dd29 {
  strings:
    $key_dd29 = { 8e 46 [2] aa 48 [2] 81 64 [2] af 46 [2] bb 5d [2] b4 47 [2] aa 5a [2] a8 5b [2] b3 5d [2] af 5a [2] b3 75 }

  condition:
    any of them
}