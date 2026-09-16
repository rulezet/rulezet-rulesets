rule TTP_XOR_QUAD_CurrentVersionRun_c638 {
  strings:
    $key_c638 = { 95 57 [2] b1 59 [2] 9a 75 [2] b4 57 [2] a0 4c [2] af 56 [2] b1 4b [2] b3 4a [2] a8 4c [2] b4 4b [2] a8 64 }

  condition:
    any of them
}