rule TTP_XOR_MULT_DOSStub_2f9d {
  strings:
    $key_2f9d = { 7b f5 [2] 0f ed [2] 48 ef [2] 0f fe [2] 41 f2 [2] 4d f8 [2] 5a f3 [2] 41 bd [2] 7c }

  condition:
    any of them
}