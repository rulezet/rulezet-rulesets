rule TTP_XOR_MULT_DOSStub_158c {
  strings:
    $key_158c = { 41 e4 [2] 35 fc [2] 72 fe [2] 35 ef [2] 7b e3 [2] 77 e9 [2] 60 e2 [2] 7b ac [2] 46 }

  condition:
    any of them
}