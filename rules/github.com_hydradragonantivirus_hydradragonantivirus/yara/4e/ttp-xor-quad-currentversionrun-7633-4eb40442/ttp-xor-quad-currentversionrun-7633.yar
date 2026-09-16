rule TTP_XOR_QUAD_CurrentVersionRun_7633 {
  strings:
    $key_7633 = { 25 5c [2] 01 52 [2] 2a 7e [2] 04 5c [2] 10 47 [2] 1f 5d [2] 01 40 [2] 03 41 [2] 18 47 [2] 04 40 [2] 18 6f }

  condition:
    any of them
}