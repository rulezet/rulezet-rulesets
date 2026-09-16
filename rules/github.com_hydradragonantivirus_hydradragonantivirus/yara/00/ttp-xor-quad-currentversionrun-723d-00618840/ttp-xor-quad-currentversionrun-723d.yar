rule TTP_XOR_QUAD_CurrentVersionRun_723d {
  strings:
    $key_723d = { 21 52 [2] 05 5c [2] 2e 70 [2] 00 52 [2] 14 49 [2] 1b 53 [2] 05 4e [2] 07 4f [2] 1c 49 [2] 00 4e [2] 1c 61 }

  condition:
    any of them
}