rule TTP_XOR_MULT_DOSStub_9dbd {
  strings:
    $key_9dbd = { c9 d5 [2] bd cd [2] fa cf [2] bd de [2] f3 d2 [2] ff d8 [2] e8 d3 [2] f3 9d [2] ce }

  condition:
    any of them
}