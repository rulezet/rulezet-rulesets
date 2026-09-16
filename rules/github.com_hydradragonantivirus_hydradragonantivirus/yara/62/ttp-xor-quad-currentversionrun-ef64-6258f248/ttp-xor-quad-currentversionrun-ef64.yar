rule TTP_XOR_QUAD_CurrentVersionRun_ef64 {
  strings:
    $key_ef64 = { bc 0b [2] 98 05 [2] b3 29 [2] 9d 0b [2] 89 10 [2] 86 0a [2] 98 17 [2] 9a 16 [2] 81 10 [2] 9d 17 [2] 81 38 }

  condition:
    any of them
}