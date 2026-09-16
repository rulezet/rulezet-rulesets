rule TTP_XOR_MULT_DOSStub_8873 {
  strings:
    $key_8873 = { dc 1b [2] a8 03 [2] ef 01 [2] a8 10 [2] e6 1c [2] ea 16 [2] fd 1d [2] e6 53 [2] db }

  condition:
    any of them
}