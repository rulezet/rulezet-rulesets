rule TTP_XOR_QUAD_CurrentVersionRun_2031 {
  strings:
    $key_2031 = { 73 5e [2] 57 50 [2] 7c 7c [2] 52 5e [2] 46 45 [2] 49 5f [2] 57 42 [2] 55 43 [2] 4e 45 [2] 52 42 [2] 4e 6d }

  condition:
    any of them
}