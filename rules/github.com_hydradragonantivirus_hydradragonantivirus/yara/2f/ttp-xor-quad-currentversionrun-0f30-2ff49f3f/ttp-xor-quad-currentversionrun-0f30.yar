rule TTP_XOR_QUAD_CurrentVersionRun_0f30 {
  strings:
    $key_0f30 = { 5c 5f [2] 78 51 [2] 53 7d [2] 7d 5f [2] 69 44 [2] 66 5e [2] 78 43 [2] 7a 42 [2] 61 44 [2] 7d 43 [2] 61 6c }

  condition:
    any of them
}