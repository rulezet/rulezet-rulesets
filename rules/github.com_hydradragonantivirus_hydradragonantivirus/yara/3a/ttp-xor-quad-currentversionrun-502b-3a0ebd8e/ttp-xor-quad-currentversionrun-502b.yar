rule TTP_XOR_QUAD_CurrentVersionRun_502b {
  strings:
    $key_502b = { 03 44 [2] 27 4a [2] 0c 66 [2] 22 44 [2] 36 5f [2] 39 45 [2] 27 58 [2] 25 59 [2] 3e 5f [2] 22 58 [2] 3e 77 }

  condition:
    any of them
}