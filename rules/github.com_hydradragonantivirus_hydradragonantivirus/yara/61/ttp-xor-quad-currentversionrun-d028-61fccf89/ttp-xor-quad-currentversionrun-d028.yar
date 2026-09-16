rule TTP_XOR_QUAD_CurrentVersionRun_d028 {
  strings:
    $key_d028 = { 83 47 [2] a7 49 [2] 8c 65 [2] a2 47 [2] b6 5c [2] b9 46 [2] a7 5b [2] a5 5a [2] be 5c [2] a2 5b [2] be 74 }

  condition:
    any of them
}