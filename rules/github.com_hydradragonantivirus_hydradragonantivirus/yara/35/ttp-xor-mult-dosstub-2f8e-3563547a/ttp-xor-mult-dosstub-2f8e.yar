rule TTP_XOR_MULT_DOSStub_2f8e {
  strings:
    $key_2f8e = { 7b e6 [2] 0f fe [2] 48 fc [2] 0f ed [2] 41 e1 [2] 4d eb [2] 5a e0 [2] 41 ae [2] 7c }

  condition:
    any of them
}