rule TTP_XOR_QUAD_CurrentVersionRun_d015 {
  strings:
    $key_d015 = { 83 7a [2] a7 74 [2] 8c 58 [2] a2 7a [2] b6 61 [2] b9 7b [2] a7 66 [2] a5 67 [2] be 61 [2] a2 66 [2] be 49 }

  condition:
    any of them
}