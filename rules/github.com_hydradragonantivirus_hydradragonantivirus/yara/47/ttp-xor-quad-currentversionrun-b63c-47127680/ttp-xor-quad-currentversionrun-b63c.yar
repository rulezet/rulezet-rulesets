rule TTP_XOR_QUAD_CurrentVersionRun_b63c {
  strings:
    $key_b63c = { e5 53 [2] c1 5d [2] ea 71 [2] c4 53 [2] d0 48 [2] df 52 [2] c1 4f [2] c3 4e [2] d8 48 [2] c4 4f [2] d8 60 }

  condition:
    any of them
}