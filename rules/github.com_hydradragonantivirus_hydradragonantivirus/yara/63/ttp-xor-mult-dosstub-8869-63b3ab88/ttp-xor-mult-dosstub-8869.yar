rule TTP_XOR_MULT_DOSStub_8869 {
  strings:
    $key_8869 = { dc 01 [2] a8 19 [2] ef 1b [2] a8 0a [2] e6 06 [2] ea 0c [2] fd 07 [2] e6 49 [2] db }

  condition:
    any of them
}