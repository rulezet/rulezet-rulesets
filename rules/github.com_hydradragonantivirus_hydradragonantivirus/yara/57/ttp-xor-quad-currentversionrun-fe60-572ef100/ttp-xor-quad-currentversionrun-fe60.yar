rule TTP_XOR_QUAD_CurrentVersionRun_fe60 {
  strings:
    $key_fe60 = { ad 0f [2] 89 01 [2] a2 2d [2] 8c 0f [2] 98 14 [2] 97 0e [2] 89 13 [2] 8b 12 [2] 90 14 [2] 8c 13 [2] 90 3c }

  condition:
    any of them
}