rule TTP_XOR_MULT_DOSStub_938c {
  strings:
    $key_938c = { c7 e4 [2] b3 fc [2] f4 fe [2] b3 ef [2] fd e3 [2] f1 e9 [2] e6 e2 [2] fd ac [2] c0 }

  condition:
    any of them
}