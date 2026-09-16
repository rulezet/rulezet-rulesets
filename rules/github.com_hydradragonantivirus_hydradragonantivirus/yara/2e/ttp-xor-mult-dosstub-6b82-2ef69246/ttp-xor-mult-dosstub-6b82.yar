rule TTP_XOR_MULT_DOSStub_6b82 {
  strings:
    $key_6b82 = { 3f ea [2] 4b f2 [2] 0c f0 [2] 4b e1 [2] 05 ed [2] 09 e7 [2] 1e ec [2] 05 a2 [2] 38 }

  condition:
    any of them
}