rule TTP_XOR_QUAD_CurrentVersionRun_ef65 {
  strings:
    $key_ef65 = { bc 0a [2] 98 04 [2] b3 28 [2] 9d 0a [2] 89 11 [2] 86 0b [2] 98 16 [2] 9a 17 [2] 81 11 [2] 9d 16 [2] 81 39 }

  condition:
    any of them
}