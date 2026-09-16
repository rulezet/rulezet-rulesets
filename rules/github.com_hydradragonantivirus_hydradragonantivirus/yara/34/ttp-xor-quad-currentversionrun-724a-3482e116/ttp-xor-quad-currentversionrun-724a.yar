rule TTP_XOR_QUAD_CurrentVersionRun_724a {
  strings:
    $key_724a = { 21 25 [2] 05 2b [2] 2e 07 [2] 00 25 [2] 14 3e [2] 1b 24 [2] 05 39 [2] 07 38 [2] 1c 3e [2] 00 39 [2] 1c 16 }

  condition:
    any of them
}