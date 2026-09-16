rule TTP_XOR_QUAD_CurrentVersionRun_2e20 {
  strings:
    $key_2e20 = { 7d 4f [2] 59 41 [2] 72 6d [2] 5c 4f [2] 48 54 [2] 47 4e [2] 59 53 [2] 5b 52 [2] 40 54 [2] 5c 53 [2] 40 7c }

  condition:
    any of them
}