rule TTP_XOR_QUAD_CurrentVersionRun_073a {
  strings:
    $key_073a = { 54 55 [2] 70 5b [2] 5b 77 [2] 75 55 [2] 61 4e [2] 6e 54 [2] 70 49 [2] 72 48 [2] 69 4e [2] 75 49 [2] 69 66 }

  condition:
    any of them
}