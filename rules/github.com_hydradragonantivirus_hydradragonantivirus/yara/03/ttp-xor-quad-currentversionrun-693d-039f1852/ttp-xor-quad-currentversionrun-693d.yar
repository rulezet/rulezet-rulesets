rule TTP_XOR_QUAD_CurrentVersionRun_693d {
  strings:
    $key_693d = { 3a 52 [2] 1e 5c [2] 35 70 [2] 1b 52 [2] 0f 49 [2] 00 53 [2] 1e 4e [2] 1c 4f [2] 07 49 [2] 1b 4e [2] 07 61 }

  condition:
    any of them
}