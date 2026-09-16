rule TTP_XOR_MULT_DOSStub_2b83 {
  strings:
    $key_2b83 = { 7f eb [2] 0b f3 [2] 4c f1 [2] 0b e0 [2] 45 ec [2] 49 e6 [2] 5e ed [2] 45 a3 [2] 78 }

  condition:
    any of them
}