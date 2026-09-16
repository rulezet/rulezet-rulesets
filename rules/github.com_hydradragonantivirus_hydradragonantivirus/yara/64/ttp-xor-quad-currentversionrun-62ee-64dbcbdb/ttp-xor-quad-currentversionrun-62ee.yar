rule TTP_XOR_QUAD_CurrentVersionRun_62ee {
  strings:
    $key_62ee = { 31 81 [2] 15 8f [2] 3e a3 [2] 10 81 [2] 04 9a [2] 0b 80 [2] 15 9d [2] 17 9c [2] 0c 9a [2] 10 9d [2] 0c b2 }

  condition:
    any of them
}