rule TTP_XOR_MULT_DOSStub_559d {
  strings:
    $key_559d = { 01 f5 [2] 75 ed [2] 32 ef [2] 75 fe [2] 3b f2 [2] 37 f8 [2] 20 f3 [2] 3b bd [2] 06 }

  condition:
    any of them
}