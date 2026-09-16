rule TTP_XOR_QUAD_CurrentVersionRun_475c {
  strings:
    $key_475c = { 14 33 [2] 30 3d [2] 1b 11 [2] 35 33 [2] 21 28 [2] 2e 32 [2] 30 2f [2] 32 2e [2] 29 28 [2] 35 2f [2] 29 00 }

  condition:
    any of them
}