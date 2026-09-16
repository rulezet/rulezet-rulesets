rule TTP_XOR_MULT_DOSStub_bccd {
  strings:
    $key_bccd = { e8 a5 [2] 9c bd [2] db bf [2] 9c ae [2] d2 a2 [2] de a8 [2] c9 a3 [2] d2 ed [2] ef }

  condition:
    any of them
}