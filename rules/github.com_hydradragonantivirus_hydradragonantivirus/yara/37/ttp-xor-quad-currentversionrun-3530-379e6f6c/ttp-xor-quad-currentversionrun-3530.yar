rule TTP_XOR_QUAD_CurrentVersionRun_3530 {
  strings:
    $key_3530 = { 66 5f [2] 42 51 [2] 69 7d [2] 47 5f [2] 53 44 [2] 5c 5e [2] 42 43 [2] 40 42 [2] 5b 44 [2] 47 43 [2] 5b 6c }

  condition:
    any of them
}