rule TTP_XOR_MULT_DOSStub_88fe {
  strings:
    $key_88fe = { dc 96 [2] a8 8e [2] ef 8c [2] a8 9d [2] e6 91 [2] ea 9b [2] fd 90 [2] e6 de [2] db }

  condition:
    any of them
}