rule TTP_XOR_MULT_DOSStub_886f {
  strings:
    $key_886f = { dc 07 [2] a8 1f [2] ef 1d [2] a8 0c [2] e6 00 [2] ea 0a [2] fd 01 [2] e6 4f [2] db }

  condition:
    any of them
}