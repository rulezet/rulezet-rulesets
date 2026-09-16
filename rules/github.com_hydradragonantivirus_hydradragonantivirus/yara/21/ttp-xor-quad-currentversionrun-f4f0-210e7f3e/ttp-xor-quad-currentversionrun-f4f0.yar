rule TTP_XOR_QUAD_CurrentVersionRun_f4f0 {
  strings:
    $key_f4f0 = { a7 9f [2] 83 91 [2] a8 bd [2] 86 9f [2] 92 84 [2] 9d 9e [2] 83 83 [2] 81 82 [2] 9a 84 [2] 86 83 [2] 9a ac }

  condition:
    any of them
}