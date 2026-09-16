rule TTP_XOR_QUAD_CurrentVersionRun_b02f {
  strings:
    $key_b02f = { e3 40 [2] c7 4e [2] ec 62 [2] c2 40 [2] d6 5b [2] d9 41 [2] c7 5c [2] c5 5d [2] de 5b [2] c2 5c [2] de 73 }

  condition:
    any of them
}