rule TTP_XOR_MULT_DOSStub_883c {
  strings:
    $key_883c = { dc 54 [2] a8 4c [2] ef 4e [2] a8 5f [2] e6 53 [2] ea 59 [2] fd 52 [2] e6 1c [2] db }

  condition:
    any of them
}