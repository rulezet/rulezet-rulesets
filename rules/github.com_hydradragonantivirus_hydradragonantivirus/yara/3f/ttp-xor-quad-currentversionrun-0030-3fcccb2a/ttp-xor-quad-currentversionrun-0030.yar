rule TTP_XOR_QUAD_CurrentVersionRun_0030 {
  strings:
    $key_0030 = { 53 5f [2] 77 51 [2] 5c 7d [2] 72 5f [2] 66 44 [2] 69 5e [2] 77 43 [2] 75 42 [2] 6e 44 [2] 72 43 [2] 6e 6c }

  condition:
    any of them
}