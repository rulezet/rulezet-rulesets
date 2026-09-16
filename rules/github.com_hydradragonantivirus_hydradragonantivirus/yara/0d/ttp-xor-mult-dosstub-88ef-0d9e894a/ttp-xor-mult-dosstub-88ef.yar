rule TTP_XOR_MULT_DOSStub_88ef {
  strings:
    $key_88ef = { dc 87 [2] a8 9f [2] ef 9d [2] a8 8c [2] e6 80 [2] ea 8a [2] fd 81 [2] e6 cf [2] db }

  condition:
    any of them
}