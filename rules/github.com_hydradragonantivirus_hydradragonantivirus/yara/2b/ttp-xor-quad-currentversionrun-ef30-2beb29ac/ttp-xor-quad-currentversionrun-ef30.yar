rule TTP_XOR_QUAD_CurrentVersionRun_ef30 {
  strings:
    $key_ef30 = { bc 5f [2] 98 51 [2] b3 7d [2] 9d 5f [2] 89 44 [2] 86 5e [2] 98 43 [2] 9a 42 [2] 81 44 [2] 9d 43 [2] 81 6c }

  condition:
    any of them
}