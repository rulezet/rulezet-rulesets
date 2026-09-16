rule TTP_XOR_MULT_DOSStub_c29c {
  strings:
    $key_c29c = { 96 f4 [2] e2 ec [2] a5 ee [2] e2 ff [2] ac f3 [2] a0 f9 [2] b7 f2 [2] ac bc [2] 91 }

  condition:
    any of them
}