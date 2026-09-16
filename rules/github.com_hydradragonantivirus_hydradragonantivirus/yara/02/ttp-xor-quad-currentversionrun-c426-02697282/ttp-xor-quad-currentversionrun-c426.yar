rule TTP_XOR_QUAD_CurrentVersionRun_c426 {
  strings:
    $key_c426 = { 97 49 [2] b3 47 [2] 98 6b [2] b6 49 [2] a2 52 [2] ad 48 [2] b3 55 [2] b1 54 [2] aa 52 [2] b6 55 [2] aa 7a }

  condition:
    any of them
}