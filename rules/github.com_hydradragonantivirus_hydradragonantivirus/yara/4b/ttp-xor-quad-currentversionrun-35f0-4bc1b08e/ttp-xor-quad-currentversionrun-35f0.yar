rule TTP_XOR_QUAD_CurrentVersionRun_35f0 {
  strings:
    $key_35f0 = { 66 9f [2] 42 91 [2] 69 bd [2] 47 9f [2] 53 84 [2] 5c 9e [2] 42 83 [2] 40 82 [2] 5b 84 [2] 47 83 [2] 5b ac }

  condition:
    any of them
}