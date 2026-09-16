rule TTP_XOR_MULT_DOSStub_dadc {
  strings:
    $key_dadc = { 8e b4 [2] fa ac [2] bd ae [2] fa bf [2] b4 b3 [2] b8 b9 [2] af b2 [2] b4 fc [2] 89 }

  condition:
    any of them
}