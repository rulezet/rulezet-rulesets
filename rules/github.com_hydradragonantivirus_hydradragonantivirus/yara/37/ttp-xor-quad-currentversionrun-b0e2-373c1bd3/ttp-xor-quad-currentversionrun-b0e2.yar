rule TTP_XOR_QUAD_CurrentVersionRun_b0e2 {
  strings:
    $key_b0e2 = { e3 8d [2] c7 83 [2] ec af [2] c2 8d [2] d6 96 [2] d9 8c [2] c7 91 [2] c5 90 [2] de 96 [2] c2 91 [2] de be }

  condition:
    any of them
}