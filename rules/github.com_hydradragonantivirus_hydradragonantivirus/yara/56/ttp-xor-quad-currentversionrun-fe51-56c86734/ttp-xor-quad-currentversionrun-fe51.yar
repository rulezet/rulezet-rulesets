rule TTP_XOR_QUAD_CurrentVersionRun_fe51 {
  strings:
    $key_fe51 = { ad 3e [2] 89 30 [2] a2 1c [2] 8c 3e [2] 98 25 [2] 97 3f [2] 89 22 [2] 8b 23 [2] 90 25 [2] 8c 22 [2] 90 0d }

  condition:
    any of them
}