rule TTP_XOR_QUAD_CurrentVersionRun_fe10 {
  strings:
    $key_fe10 = { ad 7f [2] 89 71 [2] a2 5d [2] 8c 7f [2] 98 64 [2] 97 7e [2] 89 63 [2] 8b 62 [2] 90 64 [2] 8c 63 [2] 90 4c }

  condition:
    any of them
}