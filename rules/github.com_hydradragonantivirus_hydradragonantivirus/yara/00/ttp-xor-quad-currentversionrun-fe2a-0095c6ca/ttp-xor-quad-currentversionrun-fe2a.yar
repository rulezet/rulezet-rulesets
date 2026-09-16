rule TTP_XOR_QUAD_CurrentVersionRun_fe2a {
  strings:
    $key_fe2a = { ad 45 [2] 89 4b [2] a2 67 [2] 8c 45 [2] 98 5e [2] 97 44 [2] 89 59 [2] 8b 58 [2] 90 5e [2] 8c 59 [2] 90 76 }

  condition:
    any of them
}