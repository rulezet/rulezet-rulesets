rule TTP_XOR_QUAD_CurrentVersionRun_e531 {
  strings:
    $key_e531 = { b6 5e [2] 92 50 [2] b9 7c [2] 97 5e [2] 83 45 [2] 8c 5f [2] 92 42 [2] 90 43 [2] 8b 45 [2] 97 42 [2] 8b 6d }

  condition:
    any of them
}