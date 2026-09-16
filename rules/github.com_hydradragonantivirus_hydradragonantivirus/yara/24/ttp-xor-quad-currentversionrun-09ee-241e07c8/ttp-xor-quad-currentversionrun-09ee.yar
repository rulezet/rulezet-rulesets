rule TTP_XOR_QUAD_CurrentVersionRun_09ee {
  strings:
    $key_09ee = { 5a 81 [2] 7e 8f [2] 55 a3 [2] 7b 81 [2] 6f 9a [2] 60 80 [2] 7e 9d [2] 7c 9c [2] 67 9a [2] 7b 9d [2] 67 b2 }

  condition:
    any of them
}