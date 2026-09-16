rule TTP_XOR_QUAD_CurrentVersionRun_703f {
  strings:
    $key_703f = { 23 50 [2] 07 5e [2] 2c 72 [2] 02 50 [2] 16 4b [2] 19 51 [2] 07 4c [2] 05 4d [2] 1e 4b [2] 02 4c [2] 1e 63 }

  condition:
    any of them
}