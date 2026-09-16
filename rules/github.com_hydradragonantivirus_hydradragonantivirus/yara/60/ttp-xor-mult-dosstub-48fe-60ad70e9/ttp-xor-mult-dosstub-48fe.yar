rule TTP_XOR_MULT_DOSStub_48fe {
  strings:
    $key_48fe = { 1c 96 [2] 68 8e [2] 2f 8c [2] 68 9d [2] 26 91 [2] 2a 9b [2] 3d 90 [2] 26 de [2] 1b }

  condition:
    any of them
}