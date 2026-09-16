rule TTP_XOR_QUAD_CurrentVersionRun_053a {
  strings:
    $key_053a = { 56 55 [2] 72 5b [2] 59 77 [2] 77 55 [2] 63 4e [2] 6c 54 [2] 72 49 [2] 70 48 [2] 6b 4e [2] 77 49 [2] 6b 66 }

  condition:
    any of them
}