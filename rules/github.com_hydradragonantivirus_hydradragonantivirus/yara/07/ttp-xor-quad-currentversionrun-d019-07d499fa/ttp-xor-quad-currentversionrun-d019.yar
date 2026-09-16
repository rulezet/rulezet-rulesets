rule TTP_XOR_QUAD_CurrentVersionRun_d019 {
  strings:
    $key_d019 = { 83 76 [2] a7 78 [2] 8c 54 [2] a2 76 [2] b6 6d [2] b9 77 [2] a7 6a [2] a5 6b [2] be 6d [2] a2 6a [2] be 45 }

  condition:
    any of them
}