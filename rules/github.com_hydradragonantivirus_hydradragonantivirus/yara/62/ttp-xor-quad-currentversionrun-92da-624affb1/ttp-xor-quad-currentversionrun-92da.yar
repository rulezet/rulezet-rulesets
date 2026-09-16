rule TTP_XOR_QUAD_CurrentVersionRun_92da {
  strings:
    $key_92da = { c1 b5 [2] e5 bb [2] ce 97 [2] e0 b5 [2] f4 ae [2] fb b4 [2] e5 a9 [2] e7 a8 [2] fc ae [2] e0 a9 [2] fc 86 }

  condition:
    any of them
}