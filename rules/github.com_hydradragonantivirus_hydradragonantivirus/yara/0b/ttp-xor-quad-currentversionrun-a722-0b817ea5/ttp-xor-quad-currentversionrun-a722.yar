rule TTP_XOR_QUAD_CurrentVersionRun_a722 {
  strings:
    $key_a722 = { f4 4d [2] d0 43 [2] fb 6f [2] d5 4d [2] c1 56 [2] ce 4c [2] d0 51 [2] d2 50 [2] c9 56 [2] d5 51 [2] c9 7e }

  condition:
    any of them
}