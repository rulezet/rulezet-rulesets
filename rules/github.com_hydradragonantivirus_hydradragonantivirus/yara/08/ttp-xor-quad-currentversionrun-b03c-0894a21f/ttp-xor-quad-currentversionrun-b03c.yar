rule TTP_XOR_QUAD_CurrentVersionRun_b03c {
  strings:
    $key_b03c = { e3 53 [2] c7 5d [2] ec 71 [2] c2 53 [2] d6 48 [2] d9 52 [2] c7 4f [2] c5 4e [2] de 48 [2] c2 4f [2] de 60 }

  condition:
    any of them
}