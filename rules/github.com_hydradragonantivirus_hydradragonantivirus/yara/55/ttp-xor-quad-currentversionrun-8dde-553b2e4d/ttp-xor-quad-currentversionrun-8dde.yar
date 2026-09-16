rule TTP_XOR_QUAD_CurrentVersionRun_8dde {
  strings:
    $key_8dde = { de b1 [2] fa bf [2] d1 93 [2] ff b1 [2] eb aa [2] e4 b0 [2] fa ad [2] f8 ac [2] e3 aa [2] ff ad [2] e3 82 }

  condition:
    any of them
}