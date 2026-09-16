rule TTP_XOR_QUAD_CurrentVersionRun_b076 {
  strings:
    $key_b076 = { e3 19 [2] c7 17 [2] ec 3b [2] c2 19 [2] d6 02 [2] d9 18 [2] c7 05 [2] c5 04 [2] de 02 [2] c2 05 [2] de 2a }

  condition:
    any of them
}