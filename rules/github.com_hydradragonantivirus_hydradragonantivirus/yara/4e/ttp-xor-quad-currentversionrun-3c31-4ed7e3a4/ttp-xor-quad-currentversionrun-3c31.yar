rule TTP_XOR_QUAD_CurrentVersionRun_3c31 {
  strings:
    $key_3c31 = { 6f 5e [2] 4b 50 [2] 60 7c [2] 4e 5e [2] 5a 45 [2] 55 5f [2] 4b 42 [2] 49 43 [2] 52 45 [2] 4e 42 [2] 52 6d }

  condition:
    any of them
}