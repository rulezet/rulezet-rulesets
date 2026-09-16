rule TTP_XOR_QUAD_CurrentVersionRun_b041 {
  strings:
    $key_b041 = { e3 2e [2] c7 20 [2] ec 0c [2] c2 2e [2] d6 35 [2] d9 2f [2] c7 32 [2] c5 33 [2] de 35 [2] c2 32 [2] de 1d }

  condition:
    any of them
}