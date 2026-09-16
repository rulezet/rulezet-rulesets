rule TTP_XOR_QUAD_CurrentVersionRun_fe2d {
  strings:
    $key_fe2d = { ad 42 [2] 89 4c [2] a2 60 [2] 8c 42 [2] 98 59 [2] 97 43 [2] 89 5e [2] 8b 5f [2] 90 59 [2] 8c 5e [2] 90 71 }

  condition:
    any of them
}