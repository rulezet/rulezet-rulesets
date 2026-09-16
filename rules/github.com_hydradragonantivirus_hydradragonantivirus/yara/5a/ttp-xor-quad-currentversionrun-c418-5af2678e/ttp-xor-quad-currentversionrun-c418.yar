rule TTP_XOR_QUAD_CurrentVersionRun_c418 {
  strings:
    $key_c418 = { 97 77 [2] b3 79 [2] 98 55 [2] b6 77 [2] a2 6c [2] ad 76 [2] b3 6b [2] b1 6a [2] aa 6c [2] b6 6b [2] aa 44 }

  condition:
    any of them
}