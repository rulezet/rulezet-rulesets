rule TTP_XOR_MULT_DOSStub_1f9d {
  strings:
    $key_1f9d = { 4b f5 [2] 3f ed [2] 78 ef [2] 3f fe [2] 71 f2 [2] 7d f8 [2] 6a f3 [2] 71 bd [2] 4c }

  condition:
    any of them
}