rule TTP_XOR_MULT_DOSStub_5efe {
  strings:
    $key_5efe = { 0a 96 [2] 7e 8e [2] 39 8c [2] 7e 9d [2] 30 91 [2] 3c 9b [2] 2b 90 [2] 30 de [2] 0d }

  condition:
    any of them
}