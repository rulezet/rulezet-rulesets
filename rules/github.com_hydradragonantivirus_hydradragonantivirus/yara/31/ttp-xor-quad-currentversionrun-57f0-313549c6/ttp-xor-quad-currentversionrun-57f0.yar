rule TTP_XOR_QUAD_CurrentVersionRun_57f0 {
  strings:
    $key_57f0 = { 04 9f [2] 20 91 [2] 0b bd [2] 25 9f [2] 31 84 [2] 3e 9e [2] 20 83 [2] 22 82 [2] 39 84 [2] 25 83 [2] 39 ac }

  condition:
    any of them
}