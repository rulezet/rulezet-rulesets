rule TTP_XOR_QUAD_CurrentVersionRun_c705 {
  strings:
    $key_c705 = { 94 6a [2] b0 64 [2] 9b 48 [2] b5 6a [2] a1 71 [2] ae 6b [2] b0 76 [2] b2 77 [2] a9 71 [2] b5 76 [2] a9 59 }

  condition:
    any of them
}