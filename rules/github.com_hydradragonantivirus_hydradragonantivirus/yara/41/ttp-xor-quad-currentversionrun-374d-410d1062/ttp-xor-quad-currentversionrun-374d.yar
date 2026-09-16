rule TTP_XOR_QUAD_CurrentVersionRun_374d {
  strings:
    $key_374d = { 64 22 [2] 40 2c [2] 6b 00 [2] 45 22 [2] 51 39 [2] 5e 23 [2] 40 3e [2] 42 3f [2] 59 39 [2] 45 3e [2] 59 11 }

  condition:
    any of them
}