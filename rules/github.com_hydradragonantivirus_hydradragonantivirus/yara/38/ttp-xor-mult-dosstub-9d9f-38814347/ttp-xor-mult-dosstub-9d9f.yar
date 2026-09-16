rule TTP_XOR_MULT_DOSStub_9d9f {
  strings:
    $key_9d9f = { c9 f7 [2] bd ef [2] fa ed [2] bd fc [2] f3 f0 [2] ff fa [2] e8 f1 [2] f3 bf [2] ce }

  condition:
    any of them
}