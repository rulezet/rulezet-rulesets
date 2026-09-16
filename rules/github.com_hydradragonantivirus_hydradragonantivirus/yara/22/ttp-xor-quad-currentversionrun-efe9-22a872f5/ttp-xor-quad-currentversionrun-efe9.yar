rule TTP_XOR_QUAD_CurrentVersionRun_efe9 {
  strings:
    $key_efe9 = { bc 86 [2] 98 88 [2] b3 a4 [2] 9d 86 [2] 89 9d [2] 86 87 [2] 98 9a [2] 9a 9b [2] 81 9d [2] 9d 9a [2] 81 b5 }

  condition:
    any of them
}