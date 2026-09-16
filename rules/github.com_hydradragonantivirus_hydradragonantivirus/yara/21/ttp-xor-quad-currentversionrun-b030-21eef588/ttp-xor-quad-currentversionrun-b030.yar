rule TTP_XOR_QUAD_CurrentVersionRun_b030 {
  strings:
    $key_b030 = { e3 5f [2] c7 51 [2] ec 7d [2] c2 5f [2] d6 44 [2] d9 5e [2] c7 43 [2] c5 42 [2] de 44 [2] c2 43 [2] de 6c }

  condition:
    any of them
}