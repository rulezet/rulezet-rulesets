rule TTP_XOR_QUAD_CurrentVersionRun_bdf0 {
  strings:
    $key_bdf0 = { ee 9f [2] ca 91 [2] e1 bd [2] cf 9f [2] db 84 [2] d4 9e [2] ca 83 [2] c8 82 [2] d3 84 [2] cf 83 [2] d3 ac }

  condition:
    any of them
}