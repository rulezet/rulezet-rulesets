rule TTP_XOR_QUAD_CurrentVersionRun_c738 {
  strings:
    $key_c738 = { 94 57 [2] b0 59 [2] 9b 75 [2] b5 57 [2] a1 4c [2] ae 56 [2] b0 4b [2] b2 4a [2] a9 4c [2] b5 4b [2] a9 64 }

  condition:
    any of them
}