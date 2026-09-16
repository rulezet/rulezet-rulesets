rule TTP_XOR_MULT_DOSStub_1efe {
  strings:
    $key_1efe = { 4a 96 [2] 3e 8e [2] 79 8c [2] 3e 9d [2] 70 91 [2] 7c 9b [2] 6b 90 [2] 70 de [2] 4d }

  condition:
    any of them
}