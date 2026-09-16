rule TTP_XOR_QUAD_CurrentVersionRun_f6f0 {
  strings:
    $key_f6f0 = { a5 9f [2] 81 91 [2] aa bd [2] 84 9f [2] 90 84 [2] 9f 9e [2] 81 83 [2] 83 82 [2] 98 84 [2] 84 83 [2] 98 ac }

  condition:
    any of them
}