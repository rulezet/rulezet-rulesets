rule TTP_XOR_QUAD_CurrentVersionRun_072a {
  strings:
    $key_072a = { 54 45 [2] 70 4b [2] 5b 67 [2] 75 45 [2] 61 5e [2] 6e 44 [2] 70 59 [2] 72 58 [2] 69 5e [2] 75 59 [2] 69 76 }

  condition:
    any of them
}