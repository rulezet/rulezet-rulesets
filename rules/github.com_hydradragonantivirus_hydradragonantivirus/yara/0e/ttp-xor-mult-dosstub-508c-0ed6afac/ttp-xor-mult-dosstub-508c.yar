rule TTP_XOR_MULT_DOSStub_508c {
  strings:
    $key_508c = { 04 e4 [2] 70 fc [2] 37 fe [2] 70 ef [2] 3e e3 [2] 32 e9 [2] 25 e2 [2] 3e ac [2] 03 }

  condition:
    any of them
}