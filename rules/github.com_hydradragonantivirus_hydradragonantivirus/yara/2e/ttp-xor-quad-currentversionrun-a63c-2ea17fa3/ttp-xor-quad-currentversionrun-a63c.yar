rule TTP_XOR_QUAD_CurrentVersionRun_a63c {
  strings:
    $key_a63c = { f5 53 [2] d1 5d [2] fa 71 [2] d4 53 [2] c0 48 [2] cf 52 [2] d1 4f [2] d3 4e [2] c8 48 [2] d4 4f [2] c8 60 }

  condition:
    any of them
}