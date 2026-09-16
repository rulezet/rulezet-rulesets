rule TTP_XOR_QUAD_CurrentVersionRun_35fd {
  strings:
    $key_35fd = { 66 92 [2] 42 9c [2] 69 b0 [2] 47 92 [2] 53 89 [2] 5c 93 [2] 42 8e [2] 40 8f [2] 5b 89 [2] 47 8e [2] 5b a1 }

  condition:
    any of them
}