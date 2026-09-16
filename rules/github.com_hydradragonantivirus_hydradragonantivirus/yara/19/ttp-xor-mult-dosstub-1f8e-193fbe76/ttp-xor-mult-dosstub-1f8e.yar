rule TTP_XOR_MULT_DOSStub_1f8e {
  strings:
    $key_1f8e = { 4b e6 [2] 3f fe [2] 78 fc [2] 3f ed [2] 71 e1 [2] 7d eb [2] 6a e0 [2] 71 ae [2] 4c }

  condition:
    any of them
}