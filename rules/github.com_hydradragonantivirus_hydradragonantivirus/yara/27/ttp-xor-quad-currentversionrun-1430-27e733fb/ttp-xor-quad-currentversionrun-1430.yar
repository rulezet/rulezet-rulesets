rule TTP_XOR_QUAD_CurrentVersionRun_1430 {
  strings:
    $key_1430 = { 47 5f [2] 63 51 [2] 48 7d [2] 66 5f [2] 72 44 [2] 7d 5e [2] 63 43 [2] 61 42 [2] 7a 44 [2] 66 43 [2] 7a 6c }

  condition:
    any of them
}