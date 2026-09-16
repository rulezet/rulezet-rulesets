rule TTP_XOR_MULT_DOSStub_88ed {
  strings:
    $key_88ed = { dc 85 [2] a8 9d [2] ef 9f [2] a8 8e [2] e6 82 [2] ea 88 [2] fd 83 [2] e6 cd [2] db }

  condition:
    any of them
}