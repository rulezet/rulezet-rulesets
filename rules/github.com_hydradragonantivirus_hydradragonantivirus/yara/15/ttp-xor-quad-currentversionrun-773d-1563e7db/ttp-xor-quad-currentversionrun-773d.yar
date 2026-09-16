rule TTP_XOR_QUAD_CurrentVersionRun_773d {
  strings:
    $key_773d = { 24 52 [2] 00 5c [2] 2b 70 [2] 05 52 [2] 11 49 [2] 1e 53 [2] 00 4e [2] 02 4f [2] 19 49 [2] 05 4e [2] 19 61 }

  condition:
    any of them
}