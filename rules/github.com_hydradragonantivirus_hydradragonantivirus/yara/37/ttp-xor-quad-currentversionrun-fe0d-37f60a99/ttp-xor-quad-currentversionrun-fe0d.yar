rule TTP_XOR_QUAD_CurrentVersionRun_fe0d {
  strings:
    $key_fe0d = { ad 62 [2] 89 6c [2] a2 40 [2] 8c 62 [2] 98 79 [2] 97 63 [2] 89 7e [2] 8b 7f [2] 90 79 [2] 8c 7e [2] 90 51 }

  condition:
    any of them
}