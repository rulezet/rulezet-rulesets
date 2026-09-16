rule TTP_XOR_MULT_DOSStub_7efe {
  strings:
    $key_7efe = { 2a 96 [2] 5e 8e [2] 19 8c [2] 5e 9d [2] 10 91 [2] 1c 9b [2] 0b 90 [2] 10 de [2] 2d }

  condition:
    any of them
}