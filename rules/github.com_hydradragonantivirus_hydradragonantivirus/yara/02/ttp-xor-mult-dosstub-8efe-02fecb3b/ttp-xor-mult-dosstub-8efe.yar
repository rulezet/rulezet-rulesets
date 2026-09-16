rule TTP_XOR_MULT_DOSStub_8efe {
  strings:
    $key_8efe = { da 96 [2] ae 8e [2] e9 8c [2] ae 9d [2] e0 91 [2] ec 9b [2] fb 90 [2] e0 de [2] dd }

  condition:
    any of them
}