rule TTP_XOR_QUAD_CurrentVersionRun_4b30 {
  strings:
    $key_4b30 = { 18 5f [2] 3c 51 [2] 17 7d [2] 39 5f [2] 2d 44 [2] 22 5e [2] 3c 43 [2] 3e 42 [2] 25 44 [2] 39 43 [2] 25 6c }

  condition:
    any of them
}