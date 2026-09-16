rule TTP_XOR_MULT_DOSStub_6efe {
  strings:
    $key_6efe = { 3a 96 [2] 4e 8e [2] 09 8c [2] 4e 9d [2] 00 91 [2] 0c 9b [2] 1b 90 [2] 00 de [2] 3d }

  condition:
    any of them
}