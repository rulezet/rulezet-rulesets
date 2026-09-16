rule TTP_XOR_MULT_DOSStub_dfff {
  strings:
    $key_dfff = { 8b 97 [2] ff 8f [2] b8 8d [2] ff 9c [2] b1 90 [2] bd 9a [2] aa 91 [2] b1 df [2] 8c }

  condition:
    any of them
}