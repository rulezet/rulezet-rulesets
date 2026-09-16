rule TTP_XOR_MULT_DOSStub_19ce {
  strings:
    $key_19ce = { 4d a6 [2] 39 be [2] 7e bc [2] 39 ad [2] 77 a1 [2] 7b ab [2] 6c a0 [2] 77 ee [2] 4a }

  condition:
    any of them
}