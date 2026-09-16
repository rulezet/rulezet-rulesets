rule TTP_XOR_QUAD_CurrentVersionRun_ef08 {
  strings:
    $key_ef08 = { bc 67 [2] 98 69 [2] b3 45 [2] 9d 67 [2] 89 7c [2] 86 66 [2] 98 7b [2] 9a 7a [2] 81 7c [2] 9d 7b [2] 81 54 }

  condition:
    any of them
}