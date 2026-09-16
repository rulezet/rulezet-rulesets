rule TTP_XOR_QUAD_CurrentVersionRun_ef01 {
  strings:
    $key_ef01 = { bc 6e [2] 98 60 [2] b3 4c [2] 9d 6e [2] 89 75 [2] 86 6f [2] 98 72 [2] 9a 73 [2] 81 75 [2] 9d 72 [2] 81 5d }

  condition:
    any of them
}