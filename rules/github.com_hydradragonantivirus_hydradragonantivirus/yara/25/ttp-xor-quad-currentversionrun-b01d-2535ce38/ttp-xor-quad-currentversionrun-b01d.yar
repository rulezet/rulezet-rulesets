rule TTP_XOR_QUAD_CurrentVersionRun_b01d {
  strings:
    $key_b01d = { e3 72 [2] c7 7c [2] ec 50 [2] c2 72 [2] d6 69 [2] d9 73 [2] c7 6e [2] c5 6f [2] de 69 [2] c2 6e [2] de 41 }

  condition:
    any of them
}