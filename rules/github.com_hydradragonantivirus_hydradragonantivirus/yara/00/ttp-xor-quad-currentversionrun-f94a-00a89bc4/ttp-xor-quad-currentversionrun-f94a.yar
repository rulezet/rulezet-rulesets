rule TTP_XOR_QUAD_CurrentVersionRun_f94a {
  strings:
    $key_f94a = { aa 25 [2] 8e 2b [2] a5 07 [2] 8b 25 [2] 9f 3e [2] 90 24 [2] 8e 39 [2] 8c 38 [2] 97 3e [2] 8b 39 [2] 97 16 }

  condition:
    any of them
}