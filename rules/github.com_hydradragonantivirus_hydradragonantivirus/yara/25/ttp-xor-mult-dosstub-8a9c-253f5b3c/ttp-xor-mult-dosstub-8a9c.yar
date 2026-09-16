rule TTP_XOR_MULT_DOSStub_8a9c {
  strings:
    $key_8a9c = { de f4 [2] aa ec [2] ed ee [2] aa ff [2] e4 f3 [2] e8 f9 [2] ff f2 [2] e4 bc [2] d9 }

  condition:
    any of them
}