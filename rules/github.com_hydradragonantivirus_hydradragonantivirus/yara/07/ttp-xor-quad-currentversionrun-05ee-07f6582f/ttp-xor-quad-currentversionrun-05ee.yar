rule TTP_XOR_QUAD_CurrentVersionRun_05ee {
  strings:
    $key_05ee = { 56 81 [2] 72 8f [2] 59 a3 [2] 77 81 [2] 63 9a [2] 6c 80 [2] 72 9d [2] 70 9c [2] 6b 9a [2] 77 9d [2] 6b b2 }

  condition:
    any of them
}