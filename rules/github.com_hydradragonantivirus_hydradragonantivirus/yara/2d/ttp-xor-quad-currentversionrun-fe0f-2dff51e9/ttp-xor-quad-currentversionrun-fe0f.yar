rule TTP_XOR_QUAD_CurrentVersionRun_fe0f {
  strings:
    $key_fe0f = { ad 60 [2] 89 6e [2] a2 42 [2] 8c 60 [2] 98 7b [2] 97 61 [2] 89 7c [2] 8b 7d [2] 90 7b [2] 8c 7c [2] 90 53 }

  condition:
    any of them
}