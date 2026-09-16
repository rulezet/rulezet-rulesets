rule TTP_XOR_QUAD_CurrentVersionRun_3230 {
  strings:
    $key_3230 = { 61 5f [2] 45 51 [2] 6e 7d [2] 40 5f [2] 54 44 [2] 5b 5e [2] 45 43 [2] 47 42 [2] 5c 44 [2] 40 43 [2] 5c 6c }

  condition:
    any of them
}