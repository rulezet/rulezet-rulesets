rule TTP_XOR_QUAD_CurrentVersionRun_c499 {
  strings:
    $key_c499 = { 97 f6 [2] b3 f8 [2] 98 d4 [2] b6 f6 [2] a2 ed [2] ad f7 [2] b3 ea [2] b1 eb [2] aa ed [2] b6 ea [2] aa c5 }

  condition:
    any of them
}