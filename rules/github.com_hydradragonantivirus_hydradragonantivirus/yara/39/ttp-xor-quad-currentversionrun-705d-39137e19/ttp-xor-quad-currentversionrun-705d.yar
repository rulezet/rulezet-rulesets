rule TTP_XOR_QUAD_CurrentVersionRun_705d {
  strings:
    $key_705d = { 23 32 [2] 07 3c [2] 2c 10 [2] 02 32 [2] 16 29 [2] 19 33 [2] 07 2e [2] 05 2f [2] 1e 29 [2] 02 2e [2] 1e 01 }

  condition:
    any of them
}