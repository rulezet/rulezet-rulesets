rule TTP_XOR_QUAD_CurrentVersionRun_ef25 {
  strings:
    $key_ef25 = { bc 4a [2] 98 44 [2] b3 68 [2] 9d 4a [2] 89 51 [2] 86 4b [2] 98 56 [2] 9a 57 [2] 81 51 [2] 9d 56 [2] 81 79 }

  condition:
    any of them
}