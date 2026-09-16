rule TTP_XOR_QUAD_CurrentVersionRun_2230 {
  strings:
    $key_2230 = { 71 5f [2] 55 51 [2] 7e 7d [2] 50 5f [2] 44 44 [2] 4b 5e [2] 55 43 [2] 57 42 [2] 4c 44 [2] 50 43 [2] 4c 6c }

  condition:
    any of them
}