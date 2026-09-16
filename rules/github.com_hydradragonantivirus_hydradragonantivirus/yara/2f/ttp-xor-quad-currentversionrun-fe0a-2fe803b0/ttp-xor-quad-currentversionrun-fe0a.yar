rule TTP_XOR_QUAD_CurrentVersionRun_fe0a {
  strings:
    $key_fe0a = { ad 65 [2] 89 6b [2] a2 47 [2] 8c 65 [2] 98 7e [2] 97 64 [2] 89 79 [2] 8b 78 [2] 90 7e [2] 8c 79 [2] 90 56 }

  condition:
    any of them
}