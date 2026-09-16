rule TTP_XOR_QUAD_CurrentVersionRun_34ee {
  strings:
    $key_34ee = { 67 81 [2] 43 8f [2] 68 a3 [2] 46 81 [2] 52 9a [2] 5d 80 [2] 43 9d [2] 41 9c [2] 5a 9a [2] 46 9d [2] 5a b2 }

  condition:
    any of them
}