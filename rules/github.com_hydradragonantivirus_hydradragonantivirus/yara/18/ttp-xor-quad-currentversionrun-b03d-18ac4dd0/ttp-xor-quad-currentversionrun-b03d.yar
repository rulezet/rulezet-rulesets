rule TTP_XOR_QUAD_CurrentVersionRun_b03d {
  strings:
    $key_b03d = { e3 52 [2] c7 5c [2] ec 70 [2] c2 52 [2] d6 49 [2] d9 53 [2] c7 4e [2] c5 4f [2] de 49 [2] c2 4e [2] de 61 }

  condition:
    any of them
}