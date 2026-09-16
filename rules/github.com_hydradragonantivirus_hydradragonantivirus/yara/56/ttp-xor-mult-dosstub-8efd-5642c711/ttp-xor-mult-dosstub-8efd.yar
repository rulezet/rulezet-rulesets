rule TTP_XOR_MULT_DOSStub_8efd {
  strings:
    $key_8efd = { da 95 [2] ae 8d [2] e9 8f [2] ae 9e [2] e0 92 [2] ec 98 [2] fb 93 [2] e0 dd [2] dd }

  condition:
    any of them
}