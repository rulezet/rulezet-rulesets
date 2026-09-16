rule TTP_XOR_MULT_DOSStub_9fcd {
  strings:
    $key_9fcd = { cb a5 [2] bf bd [2] f8 bf [2] bf ae [2] f1 a2 [2] fd a8 [2] ea a3 [2] f1 ed [2] cc }

  condition:
    any of them
}