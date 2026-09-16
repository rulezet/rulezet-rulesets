rule TTP_XOR_MULT_DOSStub_8501 {
  strings:
    $key_8501 = { d1 69 [2] a5 71 [2] e2 73 [2] a5 62 [2] eb 6e [2] e7 64 [2] f0 6f [2] eb 21 [2] d6 }

  condition:
    any of them
}