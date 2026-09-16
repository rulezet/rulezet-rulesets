rule TTP_XOR_MULT_DOSStub_119d {
  strings:
    $key_119d = { 45 f5 [2] 31 ed [2] 76 ef [2] 31 fe [2] 7f f2 [2] 73 f8 [2] 64 f3 [2] 7f bd [2] 42 }

  condition:
    any of them
}