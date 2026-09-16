rule TTP_XOR_QUAD_CurrentVersionRun_a0a3 {
  strings:
    $key_a0a3 = { f3 cc [2] d7 c2 [2] fc ee [2] d2 cc [2] c6 d7 [2] c9 cd [2] d7 d0 [2] d5 d1 [2] ce d7 [2] d2 d0 [2] ce ff }

  condition:
    any of them
}