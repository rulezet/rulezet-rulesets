rule TTP_XOR_MULT_DOSStub_883f {
  strings:
    $key_883f = { dc 57 [2] a8 4f [2] ef 4d [2] a8 5c [2] e6 50 [2] ea 5a [2] fd 51 [2] e6 1f [2] db }

  condition:
    any of them
}