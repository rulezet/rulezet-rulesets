rule TTP_XOR_MULT_DOSStub_3efe {
  strings:
    $key_3efe = { 6a 96 [2] 1e 8e [2] 59 8c [2] 1e 9d [2] 50 91 [2] 5c 9b [2] 4b 90 [2] 50 de [2] 6d }

  condition:
    any of them
}