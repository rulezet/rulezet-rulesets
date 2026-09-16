rule TTP_XOR_QUAD_CurrentVersionRun_c4b1 {
  strings:
    $key_c4b1 = { 97 de [2] b3 d0 [2] 98 fc [2] b6 de [2] a2 c5 [2] ad df [2] b3 c2 [2] b1 c3 [2] aa c5 [2] b6 c2 [2] aa ed }

  condition:
    any of them
}