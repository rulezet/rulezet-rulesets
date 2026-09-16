rule TTP_XOR_QUAD_CurrentVersionRun_0931 {
  strings:
    $key_0931 = { 5a 5e [2] 7e 50 [2] 55 7c [2] 7b 5e [2] 6f 45 [2] 60 5f [2] 7e 42 [2] 7c 43 [2] 67 45 [2] 7b 42 [2] 67 6d }

  condition:
    any of them
}