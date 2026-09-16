rule TTP_XOR_QUAD_CurrentVersionRun_2030 {
  strings:
    $key_2030 = { 73 5f [2] 57 51 [2] 7c 7d [2] 52 5f [2] 46 44 [2] 49 5e [2] 57 43 [2] 55 42 [2] 4e 44 [2] 52 43 [2] 4e 6c }

  condition:
    any of them
}