rule TTP_XOR_MULT_DOSStub_5f9d {
  strings:
    $key_5f9d = { 0b f5 [2] 7f ed [2] 38 ef [2] 7f fe [2] 31 f2 [2] 3d f8 [2] 2a f3 [2] 31 bd [2] 0c }

  condition:
    any of them
}