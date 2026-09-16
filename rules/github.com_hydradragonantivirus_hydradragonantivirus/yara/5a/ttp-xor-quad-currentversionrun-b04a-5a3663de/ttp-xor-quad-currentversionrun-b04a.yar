rule TTP_XOR_QUAD_CurrentVersionRun_b04a {
  strings:
    $key_b04a = { e3 25 [2] c7 2b [2] ec 07 [2] c2 25 [2] d6 3e [2] d9 24 [2] c7 39 [2] c5 38 [2] de 3e [2] c2 39 [2] de 16 }

  condition:
    any of them
}