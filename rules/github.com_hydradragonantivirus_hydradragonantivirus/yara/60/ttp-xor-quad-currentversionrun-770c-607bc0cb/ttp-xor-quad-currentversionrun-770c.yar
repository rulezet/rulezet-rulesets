rule TTP_XOR_QUAD_CurrentVersionRun_770c {
  strings:
    $key_770c = { 24 63 [2] 00 6d [2] 2b 41 [2] 05 63 [2] 11 78 [2] 1e 62 [2] 00 7f [2] 02 7e [2] 19 78 [2] 05 7f [2] 19 50 }

  condition:
    any of them
}