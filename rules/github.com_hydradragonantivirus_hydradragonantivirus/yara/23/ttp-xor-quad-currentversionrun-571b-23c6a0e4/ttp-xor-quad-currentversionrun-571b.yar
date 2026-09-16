rule TTP_XOR_QUAD_CurrentVersionRun_571b {
  strings:
    $key_571b = { 04 74 [2] 20 7a [2] 0b 56 [2] 25 74 [2] 31 6f [2] 3e 75 [2] 20 68 [2] 22 69 [2] 39 6f [2] 25 68 [2] 39 47 }

  condition:
    any of them
}