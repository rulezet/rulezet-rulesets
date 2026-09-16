rule TTP_XOR_QUAD_CurrentVersionRun_fe38 {
  strings:
    $key_fe38 = { ad 57 [2] 89 59 [2] a2 75 [2] 8c 57 [2] 98 4c [2] 97 56 [2] 89 4b [2] 8b 4a [2] 90 4c [2] 8c 4b [2] 90 64 }

  condition:
    any of them
}