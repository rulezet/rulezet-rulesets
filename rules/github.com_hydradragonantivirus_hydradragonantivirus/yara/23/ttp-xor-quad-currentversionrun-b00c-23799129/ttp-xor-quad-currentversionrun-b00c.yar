rule TTP_XOR_QUAD_CurrentVersionRun_b00c {
  strings:
    $key_b00c = { e3 63 [2] c7 6d [2] ec 41 [2] c2 63 [2] d6 78 [2] d9 62 [2] c7 7f [2] c5 7e [2] de 78 [2] c2 7f [2] de 50 }

  condition:
    any of them
}