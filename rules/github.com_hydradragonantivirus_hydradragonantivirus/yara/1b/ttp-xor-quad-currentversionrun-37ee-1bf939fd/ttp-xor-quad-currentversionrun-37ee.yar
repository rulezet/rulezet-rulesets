rule TTP_XOR_QUAD_CurrentVersionRun_37ee {
  strings:
    $key_37ee = { 64 81 [2] 40 8f [2] 6b a3 [2] 45 81 [2] 51 9a [2] 5e 80 [2] 40 9d [2] 42 9c [2] 59 9a [2] 45 9d [2] 59 b2 }

  condition:
    any of them
}