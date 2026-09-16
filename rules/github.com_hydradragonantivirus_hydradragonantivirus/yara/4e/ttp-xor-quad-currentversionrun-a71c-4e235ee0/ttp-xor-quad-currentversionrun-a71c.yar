rule TTP_XOR_QUAD_CurrentVersionRun_a71c {
  strings:
    $key_a71c = { f4 73 [2] d0 7d [2] fb 51 [2] d5 73 [2] c1 68 [2] ce 72 [2] d0 6f [2] d2 6e [2] c9 68 [2] d5 6f [2] c9 40 }

  condition:
    any of them
}