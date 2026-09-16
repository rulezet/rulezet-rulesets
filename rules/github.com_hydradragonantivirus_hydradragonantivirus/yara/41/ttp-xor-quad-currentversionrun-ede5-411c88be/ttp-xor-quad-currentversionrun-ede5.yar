rule TTP_XOR_QUAD_CurrentVersionRun_ede5 {
  strings:
    $key_ede5 = { be 8a [2] 9a 84 [2] b1 a8 [2] 9f 8a [2] 8b 91 [2] 84 8b [2] 9a 96 [2] 98 97 [2] 83 91 [2] 9f 96 [2] 83 b9 }

  condition:
    any of them
}