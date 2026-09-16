rule TTP_XOR_QUAD_CurrentVersionRun_ef3a {
  strings:
    $key_ef3a = { bc 55 [2] 98 5b [2] b3 77 [2] 9d 55 [2] 89 4e [2] 86 54 [2] 98 49 [2] 9a 48 [2] 81 4e [2] 9d 49 [2] 81 66 }

  condition:
    any of them
}