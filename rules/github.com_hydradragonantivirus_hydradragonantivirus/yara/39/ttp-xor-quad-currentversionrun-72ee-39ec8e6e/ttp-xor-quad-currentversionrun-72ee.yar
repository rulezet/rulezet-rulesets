rule TTP_XOR_QUAD_CurrentVersionRun_72ee {
  strings:
    $key_72ee = { 21 81 [2] 05 8f [2] 2e a3 [2] 00 81 [2] 14 9a [2] 1b 80 [2] 05 9d [2] 07 9c [2] 1c 9a [2] 00 9d [2] 1c b2 }

  condition:
    any of them
}