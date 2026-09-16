rule TTP_XOR_QUAD_CurrentVersionRun_2430 {
  strings:
    $key_2430 = { 77 5f [2] 53 51 [2] 78 7d [2] 56 5f [2] 42 44 [2] 4d 5e [2] 53 43 [2] 51 42 [2] 4a 44 [2] 56 43 [2] 4a 6c }

  condition:
    any of them
}