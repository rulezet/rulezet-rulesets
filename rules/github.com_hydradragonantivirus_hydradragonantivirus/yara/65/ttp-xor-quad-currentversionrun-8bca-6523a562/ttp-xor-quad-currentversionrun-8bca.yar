rule TTP_XOR_QUAD_CurrentVersionRun_8bca {
  strings:
    $key_8bca = { d8 a5 [2] fc ab [2] d7 87 [2] f9 a5 [2] ed be [2] e2 a4 [2] fc b9 [2] fe b8 [2] e5 be [2] f9 b9 [2] e5 96 }

  condition:
    any of them
}