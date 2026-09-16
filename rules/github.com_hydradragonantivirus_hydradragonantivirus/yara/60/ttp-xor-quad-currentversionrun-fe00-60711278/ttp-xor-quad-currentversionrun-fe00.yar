rule TTP_XOR_QUAD_CurrentVersionRun_fe00 {
  strings:
    $key_fe00 = { ad 6f [2] 89 61 [2] a2 4d [2] 8c 6f [2] 98 74 [2] 97 6e [2] 89 73 [2] 8b 72 [2] 90 74 [2] 8c 73 [2] 90 5c }

  condition:
    any of them
}