rule TTP_XOR_MULT_DOSStub_659d {
  strings:
    $key_659d = { 31 f5 [2] 45 ed [2] 02 ef [2] 45 fe [2] 0b f2 [2] 07 f8 [2] 10 f3 [2] 0b bd [2] 36 }

  condition:
    any of them
}