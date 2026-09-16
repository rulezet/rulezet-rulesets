rule TTP_XOR_QUAD_CurrentVersionRun_215d {
  strings:
    $key_215d = { 72 32 [2] 56 3c [2] 7d 10 [2] 53 32 [2] 47 29 [2] 48 33 [2] 56 2e [2] 54 2f [2] 4f 29 [2] 53 2e [2] 4f 01 }

  condition:
    any of them
}