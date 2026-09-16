rule TTP_XOR_QUAD_CurrentVersionRun_726d {
  strings:
    $key_726d = { 21 02 [2] 05 0c [2] 2e 20 [2] 00 02 [2] 14 19 [2] 1b 03 [2] 05 1e [2] 07 1f [2] 1c 19 [2] 00 1e [2] 1c 31 }

  condition:
    any of them
}