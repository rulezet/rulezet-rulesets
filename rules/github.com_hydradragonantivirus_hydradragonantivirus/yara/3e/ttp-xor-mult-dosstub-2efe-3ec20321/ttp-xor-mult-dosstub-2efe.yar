rule TTP_XOR_MULT_DOSStub_2efe {
  strings:
    $key_2efe = { 7a 96 [2] 0e 8e [2] 49 8c [2] 0e 9d [2] 40 91 [2] 4c 9b [2] 5b 90 [2] 40 de [2] 7d }

  condition:
    any of them
}