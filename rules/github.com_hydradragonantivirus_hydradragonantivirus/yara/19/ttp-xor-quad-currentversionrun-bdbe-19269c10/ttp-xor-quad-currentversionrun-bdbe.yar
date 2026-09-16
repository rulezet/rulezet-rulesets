rule TTP_XOR_QUAD_CurrentVersionRun_bdbe {
  strings:
    $key_bdbe = { ee d1 [2] ca df [2] e1 f3 [2] cf d1 [2] db ca [2] d4 d0 [2] ca cd [2] c8 cc [2] d3 ca [2] cf cd [2] d3 e2 }

  condition:
    any of them
}