rule TTP_XOR_MULT_DOSStub_fcdc {
  strings:
    $key_fcdc = { a8 b4 [2] dc ac [2] 9b ae [2] dc bf [2] 92 b3 [2] 9e b9 [2] 89 b2 [2] 92 fc [2] af }

  condition:
    any of them
}