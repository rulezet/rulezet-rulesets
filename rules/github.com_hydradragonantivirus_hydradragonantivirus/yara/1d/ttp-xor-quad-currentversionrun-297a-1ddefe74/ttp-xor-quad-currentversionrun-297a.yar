rule TTP_XOR_QUAD_CurrentVersionRun_297a {
  strings:
    $key_297a = { 7a 15 [2] 5e 1b [2] 75 37 [2] 5b 15 [2] 4f 0e [2] 40 14 [2] 5e 09 [2] 5c 08 [2] 47 0e [2] 5b 09 [2] 47 26 }

  condition:
    any of them
}