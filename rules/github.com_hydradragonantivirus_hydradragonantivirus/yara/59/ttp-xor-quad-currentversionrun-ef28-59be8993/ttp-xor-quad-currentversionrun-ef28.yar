rule TTP_XOR_QUAD_CurrentVersionRun_ef28 {
  strings:
    $key_ef28 = { bc 47 [2] 98 49 [2] b3 65 [2] 9d 47 [2] 89 5c [2] 86 46 [2] 98 5b [2] 9a 5a [2] 81 5c [2] 9d 5b [2] 81 74 }

  condition:
    any of them
}