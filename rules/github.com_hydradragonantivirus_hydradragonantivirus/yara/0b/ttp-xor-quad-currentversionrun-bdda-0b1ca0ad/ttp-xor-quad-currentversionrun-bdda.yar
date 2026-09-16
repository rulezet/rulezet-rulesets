rule TTP_XOR_QUAD_CurrentVersionRun_bdda {
  strings:
    $key_bdda = { ee b5 [2] ca bb [2] e1 97 [2] cf b5 [2] db ae [2] d4 b4 [2] ca a9 [2] c8 a8 [2] d3 ae [2] cf a9 [2] d3 86 }

  condition:
    any of them
}