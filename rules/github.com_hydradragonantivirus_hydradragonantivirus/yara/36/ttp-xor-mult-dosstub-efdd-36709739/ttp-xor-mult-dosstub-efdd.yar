rule TTP_XOR_MULT_DOSStub_efdd {
  strings:
    $key_efdd = { bb b5 [2] cf ad [2] 88 af [2] cf be [2] 81 b2 [2] 8d b8 [2] 9a b3 [2] 81 fd [2] bc }

  condition:
    any of them
}