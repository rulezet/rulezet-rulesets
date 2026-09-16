rule TTP_XOR_QUAD_CurrentVersionRun_f0f0 {
  strings:
    $key_f0f0 = { a3 9f [2] 87 91 [2] ac bd [2] 82 9f [2] 96 84 [2] 99 9e [2] 87 83 [2] 85 82 [2] 9e 84 [2] 82 83 [2] 9e ac }

  condition:
    any of them
}