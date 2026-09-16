rule TTP_XOR_QUAD_CurrentVersionRun_bd21 {
  strings:
    $key_bd21 = { ee 4e [2] ca 40 [2] e1 6c [2] cf 4e [2] db 55 [2] d4 4f [2] ca 52 [2] c8 53 [2] d3 55 [2] cf 52 [2] d3 7d }

  condition:
    any of them
}