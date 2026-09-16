rule TTP_XOR_QUAD_CurrentVersionRun_e272 {
  strings:
    $key_e272 = { b1 1d [2] 95 13 [2] be 3f [2] 90 1d [2] 84 06 [2] 8b 1c [2] 95 01 [2] 97 00 [2] 8c 06 [2] 90 01 [2] 8c 2e }

  condition:
    any of them
}