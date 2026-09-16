rule TTP_XOR_QUAD_CurrentVersionRun_ef1a {
  strings:
    $key_ef1a = { bc 75 [2] 98 7b [2] b3 57 [2] 9d 75 [2] 89 6e [2] 86 74 [2] 98 69 [2] 9a 68 [2] 81 6e [2] 9d 69 [2] 81 46 }

  condition:
    any of them
}