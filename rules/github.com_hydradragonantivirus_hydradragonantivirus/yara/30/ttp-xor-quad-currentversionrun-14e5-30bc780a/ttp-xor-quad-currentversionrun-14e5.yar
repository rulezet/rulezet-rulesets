rule TTP_XOR_QUAD_CurrentVersionRun_14e5 {
  strings:
    $key_14e5 = { 47 8a [2] 63 84 [2] 48 a8 [2] 66 8a [2] 72 91 [2] 7d 8b [2] 63 96 [2] 61 97 [2] 7a 91 [2] 66 96 [2] 7a b9 }

  condition:
    any of them
}