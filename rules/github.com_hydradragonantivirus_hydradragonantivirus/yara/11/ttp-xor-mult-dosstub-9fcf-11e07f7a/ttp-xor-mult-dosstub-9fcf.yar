rule TTP_XOR_MULT_DOSStub_9fcf {
  strings:
    $key_9fcf = { cb a7 [2] bf bf [2] f8 bd [2] bf ac [2] f1 a0 [2] fd aa [2] ea a1 [2] f1 ef [2] cc }

  condition:
    any of them
}