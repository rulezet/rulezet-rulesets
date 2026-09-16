rule TTP_XOR_MULT_DOSStub_deaf {
  strings:
    $key_deaf = { 8a c7 [2] fe df [2] b9 dd [2] fe cc [2] b0 c0 [2] bc ca [2] ab c1 [2] b0 8f [2] 8d }

  condition:
    any of them
}