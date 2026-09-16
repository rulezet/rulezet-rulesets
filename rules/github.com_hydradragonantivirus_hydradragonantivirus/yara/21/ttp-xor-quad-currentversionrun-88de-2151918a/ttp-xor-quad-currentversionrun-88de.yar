rule TTP_XOR_QUAD_CurrentVersionRun_88de {
  strings:
    $key_88de = { db b1 [2] ff bf [2] d4 93 [2] fa b1 [2] ee aa [2] e1 b0 [2] ff ad [2] fd ac [2] e6 aa [2] fa ad [2] e6 82 }

  condition:
    any of them
}