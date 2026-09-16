rule TTP_XOR_MULT_DOSStub_6f9d {
  strings:
    $key_6f9d = { 3b f5 [2] 4f ed [2] 08 ef [2] 4f fe [2] 01 f2 [2] 0d f8 [2] 1a f3 [2] 01 bd [2] 3c }

  condition:
    any of them
}