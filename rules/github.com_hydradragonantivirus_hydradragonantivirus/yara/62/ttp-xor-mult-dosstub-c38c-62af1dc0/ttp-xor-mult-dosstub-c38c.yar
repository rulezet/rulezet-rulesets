rule TTP_XOR_MULT_DOSStub_c38c {
  strings:
    $key_c38c = { 97 e4 [2] e3 fc [2] a4 fe [2] e3 ef [2] ad e3 [2] a1 e9 [2] b6 e2 [2] ad ac [2] 90 }

  condition:
    any of them
}