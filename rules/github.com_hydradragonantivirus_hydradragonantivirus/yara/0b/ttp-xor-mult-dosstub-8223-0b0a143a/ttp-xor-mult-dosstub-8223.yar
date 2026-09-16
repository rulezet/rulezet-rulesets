rule TTP_XOR_MULT_DOSStub_8223 {
  strings:
    $key_8223 = { d6 4b [2] a2 53 [2] e5 51 [2] a2 40 [2] ec 4c [2] e0 46 [2] f7 4d [2] ec 03 [2] d1 }

  condition:
    any of them
}