rule TTP_XOR_QUAD_CurrentVersionRun_19ee {
  strings:
    $key_19ee = { 4a 81 [2] 6e 8f [2] 45 a3 [2] 6b 81 [2] 7f 9a [2] 70 80 [2] 6e 9d [2] 6c 9c [2] 77 9a [2] 6b 9d [2] 77 b2 }

  condition:
    any of them
}