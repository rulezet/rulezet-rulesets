rule TTP_XOR_QUAD_CurrentVersionRun_497c {
  strings:
    $key_497c = { 1a 13 [2] 3e 1d [2] 15 31 [2] 3b 13 [2] 2f 08 [2] 20 12 [2] 3e 0f [2] 3c 0e [2] 27 08 [2] 3b 0f [2] 27 20 }

  condition:
    any of them
}