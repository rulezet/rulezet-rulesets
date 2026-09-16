rule TTP_XOR_MULT_DOSStub_8acd {
  strings:
    $key_8acd = { de a5 [2] aa bd [2] ed bf [2] aa ae [2] e4 a2 [2] e8 a8 [2] ff a3 [2] e4 ed [2] d9 }

  condition:
    any of them
}