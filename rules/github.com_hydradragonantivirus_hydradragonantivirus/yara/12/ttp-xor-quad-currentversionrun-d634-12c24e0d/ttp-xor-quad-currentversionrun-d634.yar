rule TTP_XOR_QUAD_CurrentVersionRun_d634 {
  strings:
    $key_d634 = { 85 5b [2] a1 55 [2] 8a 79 [2] a4 5b [2] b0 40 [2] bf 5a [2] a1 47 [2] a3 46 [2] b8 40 [2] a4 47 [2] b8 68 }

  condition:
    any of them
}