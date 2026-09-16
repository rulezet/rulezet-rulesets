rule TTP_XOR_QUAD_CurrentVersionRun_fe08 {
  strings:
    $key_fe08 = { ad 67 [2] 89 69 [2] a2 45 [2] 8c 67 [2] 98 7c [2] 97 66 [2] 89 7b [2] 8b 7a [2] 90 7c [2] 8c 7b [2] 90 54 }

  condition:
    any of them
}