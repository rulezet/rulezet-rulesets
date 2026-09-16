rule TTP_XOR_QUAD_CurrentVersionRun_fe14 {
  strings:
    $key_fe14 = { ad 7b [2] 89 75 [2] a2 59 [2] 8c 7b [2] 98 60 [2] 97 7a [2] 89 67 [2] 8b 66 [2] 90 60 [2] 8c 67 [2] 90 48 }

  condition:
    any of them
}