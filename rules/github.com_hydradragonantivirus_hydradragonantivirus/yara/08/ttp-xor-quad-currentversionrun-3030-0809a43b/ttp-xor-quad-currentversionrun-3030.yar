rule TTP_XOR_QUAD_CurrentVersionRun_3030 {
  strings:
    $key_3030 = { 63 5f [2] 47 51 [2] 6c 7d [2] 42 5f [2] 56 44 [2] 59 5e [2] 47 43 [2] 45 42 [2] 5e 44 [2] 42 43 [2] 5e 6c }

  condition:
    any of them
}