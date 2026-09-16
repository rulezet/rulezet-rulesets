rule TTP_XOR_MULT_DOSStub_ecaf {
  strings:
    $key_ecaf = { b8 c7 [2] cc df [2] 8b dd [2] cc cc [2] 82 c0 [2] 8e ca [2] 99 c1 [2] 82 8f [2] bf }

  condition:
    any of them
}