rule TTP_XOR_QUAD_CurrentVersionRun_ef1d {
  strings:
    $key_ef1d = { bc 72 [2] 98 7c [2] b3 50 [2] 9d 72 [2] 89 69 [2] 86 73 [2] 98 6e [2] 9a 6f [2] 81 69 [2] 9d 6e [2] 81 41 }

  condition:
    any of them
}