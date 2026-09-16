rule TTP_XOR_QUAD_CurrentVersionRun_52ee {
  strings:
    $key_52ee = { 01 81 [2] 25 8f [2] 0e a3 [2] 20 81 [2] 34 9a [2] 3b 80 [2] 25 9d [2] 27 9c [2] 3c 9a [2] 20 9d [2] 3c b2 }

  condition:
    any of them
}