rule TTP_XOR_QUAD_CurrentVersionRun_fe12 {
  strings:
    $key_fe12 = { ad 7d [2] 89 73 [2] a2 5f [2] 8c 7d [2] 98 66 [2] 97 7c [2] 89 61 [2] 8b 60 [2] 90 66 [2] 8c 61 [2] 90 4e }

  condition:
    any of them
}