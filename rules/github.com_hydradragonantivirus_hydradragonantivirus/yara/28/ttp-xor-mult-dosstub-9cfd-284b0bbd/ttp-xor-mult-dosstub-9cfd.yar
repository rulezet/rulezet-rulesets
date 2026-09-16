rule TTP_XOR_MULT_DOSStub_9cfd {
  strings:
    $key_9cfd = { c8 95 [2] bc 8d [2] fb 8f [2] bc 9e [2] f2 92 [2] fe 98 [2] e9 93 [2] f2 dd [2] cf }

  condition:
    any of them
}