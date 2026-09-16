rule TTP_XOR_MULT_DOSStub_518c {
  strings:
    $key_518c = { 05 e4 [2] 71 fc [2] 36 fe [2] 71 ef [2] 3f e3 [2] 33 e9 [2] 24 e2 [2] 3f ac [2] 02 }

  condition:
    any of them
}