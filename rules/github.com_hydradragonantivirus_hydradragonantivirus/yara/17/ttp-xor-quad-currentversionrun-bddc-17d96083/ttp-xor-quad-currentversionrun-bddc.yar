rule TTP_XOR_QUAD_CurrentVersionRun_bddc {
  strings:
    $key_bddc = { ee b3 [2] ca bd [2] e1 91 [2] cf b3 [2] db a8 [2] d4 b2 [2] ca af [2] c8 ae [2] d3 a8 [2] cf af [2] d3 80 }

  condition:
    any of them
}