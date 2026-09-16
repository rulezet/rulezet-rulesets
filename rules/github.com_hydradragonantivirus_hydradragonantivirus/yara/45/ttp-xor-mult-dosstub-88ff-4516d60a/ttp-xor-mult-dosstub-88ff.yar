rule TTP_XOR_MULT_DOSStub_88ff {
  strings:
    $key_88ff = { dc 97 [2] a8 8f [2] ef 8d [2] a8 9c [2] e6 90 [2] ea 9a [2] fd 91 [2] e6 df [2] db }

  condition:
    any of them
}