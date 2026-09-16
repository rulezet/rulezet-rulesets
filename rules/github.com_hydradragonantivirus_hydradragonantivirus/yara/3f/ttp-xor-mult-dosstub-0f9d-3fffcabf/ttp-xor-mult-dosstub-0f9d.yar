rule TTP_XOR_MULT_DOSStub_0f9d {
  strings:
    $key_0f9d = { 5b f5 [2] 2f ed [2] 68 ef [2] 2f fe [2] 61 f2 [2] 6d f8 [2] 7a f3 [2] 61 bd [2] 5c }

  condition:
    any of them
}