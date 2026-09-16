rule TTP_XOR_QUAD_CurrentVersionRun_572e {
  strings:
    $key_572e = { 04 41 [2] 20 4f [2] 0b 63 [2] 25 41 [2] 31 5a [2] 3e 40 [2] 20 5d [2] 22 5c [2] 39 5a [2] 25 5d [2] 39 72 }

  condition:
    any of them
}