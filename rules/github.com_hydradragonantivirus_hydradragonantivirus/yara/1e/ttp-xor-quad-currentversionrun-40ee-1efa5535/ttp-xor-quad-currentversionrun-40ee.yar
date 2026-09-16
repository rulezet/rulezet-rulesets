rule TTP_XOR_QUAD_CurrentVersionRun_40ee {
  strings:
    $key_40ee = { 13 81 [2] 37 8f [2] 1c a3 [2] 32 81 [2] 26 9a [2] 29 80 [2] 37 9d [2] 35 9c [2] 2e 9a [2] 32 9d [2] 2e b2 }

  condition:
    any of them
}