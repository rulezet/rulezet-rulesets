rule TTP_XOR_MULT_DOSStub_748c {
  strings:
    $key_748c = { 20 e4 [2] 54 fc [2] 13 fe [2] 54 ef [2] 1a e3 [2] 16 e9 [2] 01 e2 [2] 1a ac [2] 27 }

  condition:
    any of them
}