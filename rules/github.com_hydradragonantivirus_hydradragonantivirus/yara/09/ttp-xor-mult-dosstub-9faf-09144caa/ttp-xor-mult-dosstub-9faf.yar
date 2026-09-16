rule TTP_XOR_MULT_DOSStub_9faf {
  strings:
    $key_9faf = { cb c7 [2] bf df [2] f8 dd [2] bf cc [2] f1 c0 [2] fd ca [2] ea c1 [2] f1 8f [2] cc }

  condition:
    any of them
}