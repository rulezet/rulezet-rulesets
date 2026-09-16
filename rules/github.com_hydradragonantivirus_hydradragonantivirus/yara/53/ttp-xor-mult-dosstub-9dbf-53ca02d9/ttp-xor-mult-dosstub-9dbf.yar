rule TTP_XOR_MULT_DOSStub_9dbf {
  strings:
    $key_9dbf = { c9 d7 [2] bd cf [2] fa cd [2] bd dc [2] f3 d0 [2] ff da [2] e8 d1 [2] f3 9f [2] ce }

  condition:
    any of them
}