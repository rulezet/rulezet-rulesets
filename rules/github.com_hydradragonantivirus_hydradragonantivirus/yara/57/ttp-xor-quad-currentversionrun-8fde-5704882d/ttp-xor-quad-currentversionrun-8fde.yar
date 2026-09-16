rule TTP_XOR_QUAD_CurrentVersionRun_8fde {
  strings:
    $key_8fde = { dc b1 [2] f8 bf [2] d3 93 [2] fd b1 [2] e9 aa [2] e6 b0 [2] f8 ad [2] fa ac [2] e1 aa [2] fd ad [2] e1 82 }

  condition:
    any of them
}