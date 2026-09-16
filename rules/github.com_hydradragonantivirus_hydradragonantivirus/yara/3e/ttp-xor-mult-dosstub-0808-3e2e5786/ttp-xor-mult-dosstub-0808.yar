rule TTP_XOR_MULT_DOSStub_0808 {
  strings:
    $key_0808 = { 5c 60 [2] 28 78 [2] 6f 7a [2] 28 6b [2] 66 67 [2] 6a 6d [2] 7d 66 [2] 66 28 [2] 5b }

  condition:
    any of them
}